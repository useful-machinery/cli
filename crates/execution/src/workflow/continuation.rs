use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use super::admission::{ResolvedInput, ResolvedInputs};
use super::document::{DeclaredWorkspace, FailurePolicy, Output};
use super::local_run::LocalRunDirectoryError;
use super::resolution::{ResolvedWorkflow, resolve_workflow_file};
use super::runtime::StepState;
use super::validated::{
    ResolvedOutputSource, ResolvedValueSource, Scheduling, StepWorkspace, ValidatedEdgeTarget,
    ValidatedMessageSource, ValidatedStep, ValidatedWorkflow, WorkflowNode, WorkflowNodeRole,
    WorkflowValueType,
};
use super::wait::{ExecutionRootStep, Operand, WaitRecord, WaitRelease, parse_where};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Partition {
    pub(crate) reexecuted: Vec<String>,
    pub(crate) revalidated: Vec<String>,
    pub(crate) inherited: Vec<String>,
    pub(crate) rebuilt: Vec<String>,
}

/// Resolve selections against the new definition, never against the prior attempt. The
/// validated presentation order is Kahn order with source-index tie breaking. An
/// edge-scheduled continuation names exactly one step and also re-executes every step in
/// `unfinished`, those the prior attempt left neither succeeded nor inherited, so the walk
/// restarts from the named step and reaches or leaves each of them `not_reached`; a
/// dataflow caller passes an empty set.
pub(crate) fn partition(
    workflow: &ValidatedWorkflow,
    from: &[String],
    unfinished: &BTreeSet<String>,
    lost: &BTreeSet<String>,
    reusable: &BTreeSet<String>,
) -> Result<Partition, Vec<String>> {
    let mut seen = BTreeSet::new();
    let invalid = from
        .iter()
        .filter(|id| !seen.insert((*id).clone()) || !workflow.steps.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    if from.is_empty() || !invalid.is_empty() {
        return Err(invalid);
    }
    let edges = matches!(workflow.scheduling, Scheduling::Edges { .. });
    if edges && from.len() > 1 {
        return Err(from[1..].to_vec());
    }

    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for id in &workflow.presentation_order {
        let Some(step) = workflow.steps.get(id) else {
            return Err(vec![id.clone()]);
        };
        for prerequisite in &step.common().prerequisites {
            dependents
                .entry(&prerequisite.producer)
                .or_default()
                .push(id);
        }
        // An edge-scheduled step has no prerequisites; the later steps its edges can start,
        // a wait's hand-back step among them, are its dependents, so a resume re-executes
        // the walk from it. An edge naming the step itself or an earlier step adds none, so
        // the producer a continued step reads stays inherited.
        if let ValidatedStep::Workflow(step) = step {
            let mut targets = Vec::new();
            for target in step.edges.values() {
                edge_step_targets(target, &mut targets);
            }
            let position = |step: &str| workflow.source_order.iter().position(|id| id == step);
            let producer = position(id);
            dependents.entry(id).or_default().extend(
                targets
                    .into_iter()
                    .filter(|target| position(target) > producer),
            );
        }
    }
    let mut reexecuted = dependent_closure(from, &dependents);
    let mut rebuilt = Vec::new();
    if edges {
        reexecuted.extend(unfinished.iter().map(String::as_str));
    } else {
        // Each consumer of a lost workspace also selects its establishing step. Following
        // these links and the ordinary dependents gives the full closure.
        let lost_new = lost
            .iter()
            .filter(|id| {
                workflow
                    .steps
                    .get(*id)
                    .is_some_and(|step| step.common().workspace_use == DeclaredWorkspace::New)
            })
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !lost_new.is_empty() {
            for (id, step) in &workflow.steps {
                let common = step.common();
                if matches!(
                    common.workspace_use,
                    DeclaredWorkspace::Read | DeclaredWorkspace::Write
                ) && let StepWorkspace::Established { by } = &common.workspace
                    && lost_new.contains(by.as_str())
                {
                    dependents.entry(id).or_default().push(by);
                }
            }
            let expanded = dependent_closure(from, &dependents);
            rebuilt = workflow
                .presentation_order
                .iter()
                .filter(|id| {
                    lost_new.contains(id.as_str())
                        && expanded.contains(id.as_str())
                        && !reexecuted.contains(id.as_str())
                })
                .cloned()
                .collect();
            reexecuted = expanded;
        }
    }
    let mut partition = Partition {
        reexecuted: Vec::new(),
        revalidated: Vec::new(),
        inherited: Vec::new(),
        rebuilt,
    };
    let mut outright = BTreeSet::new();
    for id in &workflow.presentation_order {
        if !reexecuted.contains(id.as_str()) {
            partition.inherited.push(id.clone());
            continue;
        }
        let step = workflow.steps[id].common();
        if edges
            || !reusable.contains(id)
            || seen.contains(id)
            || (step.workspace_use == DeclaredWorkspace::New && lost.contains(id))
            || step.prerequisites.iter().any(|p| p.disposition_control)
            || !revalidation_basis(workflow, id).1.is_disjoint(&outright)
        {
            partition.reexecuted.push(id.clone());
            outright.insert(id.clone());
        } else {
            partition.revalidated.push(id.clone());
        }
    }
    Ok(partition)
}

/// Outputs that must be reproduced and workspace steps whose effects must stay unchanged.
pub(crate) fn revalidation_basis(
    workflow: &ValidatedWorkflow,
    id: &str,
) -> (BTreeMap<String, BTreeSet<String>>, BTreeSet<String>) {
    let step = &workflow.steps[id];
    let common = step.common();
    let mut references = BTreeSet::new();
    check_step_references(step, &mut references);
    let mut reproduced = BTreeMap::<String, BTreeSet<String>>::new();
    let mut unchanged = BTreeSet::new();
    if matches!(
        common.workspace_use,
        DeclaredWorkspace::Read | DeclaredWorkspace::Write
    ) {
        if let StepWorkspace::Established { by } = &common.workspace {
            if common.workspace_use == DeclaredWorkspace::Write {
                unchanged.insert(by.clone());
            } else {
                reproduced.entry(by.clone()).or_default();
                check_step_references(&workflow.steps[by], &mut references);
            }
        }
        let mut visited = BTreeSet::new();
        let mut ancestors: Vec<_> = common.prerequisites.iter().collect();
        while let Some(prerequisite) = ancestors.pop() {
            if visited.insert(&prerequisite.producer) {
                let ancestor = workflow.steps[&prerequisite.producer].common();
                if ancestor.workspace_use == DeclaredWorkspace::Write
                    && ancestor.workspace == common.workspace
                {
                    unchanged.insert(prerequisite.producer.clone());
                }
                ancestors.extend(&ancestor.prerequisites);
            }
        }
    }
    for source in references {
        reproduced
            .entry(source.node.id)
            .or_default()
            .insert(source.output);
    }
    (reproduced, unchanged)
}

fn dependent_closure<'a>(
    from: &'a [String],
    dependents: &BTreeMap<&'a str, Vec<&'a str>>,
) -> BTreeSet<&'a str> {
    let mut selected = from.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let mut queue = from.iter().map(String::as_str).collect::<VecDeque<_>>();
    while let Some(id) = queue.pop_front() {
        for dependent in dependents.get(id).into_iter().flatten() {
            if selected.insert(dependent) {
                queue.push_back(dependent);
            }
        }
    }
    selected
}

/// The steps an edge can start: a step target, a wait's `then` and `onHandBack`, and a
/// limited edge's `then` and `else`; an exit starts none.
fn edge_step_targets<'a>(target: &'a ValidatedEdgeTarget, targets: &mut Vec<&'a str>) {
    match target {
        ValidatedEdgeTarget::Step(id) => targets.push(id),
        ValidatedEdgeTarget::Exit(_) => {}
        ValidatedEdgeTarget::Limited { then, else_, .. }
        | ValidatedEdgeTarget::HostWait { then, else_, .. } => {
            targets.push(then);
            edge_step_targets(else_, targets);
        }
        ValidatedEdgeTarget::Wait {
            then, on_hand_back, ..
        } => {
            edge_step_targets(then, targets);
            targets.extend(on_hand_back.as_deref());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorState {
    Succeeded,
    Skipped,
    Inherited,
    Unsatisfied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionViolation {
    InvalidFrom {
        id: String,
    },
    Node {
        id: String,
        prior: Option<PriorState>,
    },
    RequiredSkipped {
        consumer: String,
        producer: String,
    },
    Reference {
        reference: String,
    },
    HandoverExecutionRootRequired {
        id: String,
        child: Option<String>,
    },
}

/// Judge both ways out of the wait against the same tree and the just-ended attempt.
/// Traverse their selected steps together so a shared child is read and reported once.
pub async fn wait_release<Output>(
    workflow: &ResolvedWorkflow,
    wait: &WaitRecord,
    steps: &BTreeMap<String, StepState<Output>>,
    copy_root: PathBuf,
) -> Result<WaitRelease, LocalRunDirectoryError> {
    let unfinished = steps
        .iter()
        .filter(|(_, state)| {
            !matches!(
                state,
                StepState::Succeeded { .. } | StepState::Inherited { .. }
            )
        })
        .map(|(id, _)| id.clone())
        .collect();
    let empty = BTreeSet::new();
    let partitions = std::iter::once(&wait.then)
        .chain(&wait.on_hand_back)
        .map(|target| {
            partition(
                &workflow.definition,
                std::slice::from_ref(target),
                &unfinished,
                &empty,
                &empty,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LocalRunDirectoryError::WaitRecordInvalid)?;

    let definition = workflow.definition.clone();
    let violations = tokio::task::spawn_blocking(move || {
        handover_violations(&definition, &partitions, Some(&copy_root))
    })
    .await
    .map_err(|_| LocalRunDirectoryError::StateWriteUnavailable)?;
    let steps = violations
        .into_iter()
        .map(|violation| match violation {
            AdmissionViolation::HandoverExecutionRootRequired { id, child } => {
                Ok(ExecutionRootStep { id, child })
            }
            _ => Err(LocalRunDirectoryError::WaitRecordInvalid),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WaitRelease {
        permitted: steps.is_empty(),
        execution_root_steps: (!steps.is_empty()).then_some(steps),
    })
}

pub(crate) fn handover_violations(
    workflow: &ValidatedWorkflow,
    partitions: &[Partition],
    copy_root: Option<&Path>,
) -> Vec<AdmissionViolation> {
    let mut pending = partitions
        .iter()
        .flat_map(|partition| partition.reexecuted.iter().chain(&partition.revalidated))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    let mut children = BTreeMap::new();
    let mut violations = Vec::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let step = &workflow.steps[id];
        match step {
            ValidatedStep::Workflow(stage) => {
                // Later attempts can take a backward edge in this same execution root.
                for target in stage.edges.values() {
                    edge_step_targets(target, &mut pending);
                }
                let paths = copy_root.and_then(|root| {
                    child_execution_root_steps(root, &stage.workflow, &mut children)
                });
                match paths {
                    Some(paths) => violations.extend(paths.into_iter().map(|child| {
                        AdmissionViolation::HandoverExecutionRootRequired {
                            id: id.to_owned(),
                            child: Some(child),
                        }
                    })),
                    None => violations.push(AdmissionViolation::HandoverExecutionRootRequired {
                        id: id.to_owned(),
                        child: None,
                    }),
                }
            }
            ValidatedStep::Command(_) | ValidatedStep::Agent(_) => {
                if step.common().workspace == StepWorkspace::Starting {
                    violations.push(AdmissionViolation::HandoverExecutionRootRequired {
                        id: id.to_owned(),
                        child: None,
                    });
                }
            }
        }
    }
    sort_violations(&mut violations, workflow);
    violations
}

/// Relative step paths in a child that require the execution root. An unreadable child or
/// a recursive file reference makes the calling workflow step ineligible.
fn child_execution_root_steps(
    root: &Path,
    file: &str,
    files: &mut BTreeMap<String, Option<Vec<String>>>,
) -> Option<Vec<String>> {
    if let Some(paths) = files.get(file) {
        return paths.clone();
    }
    files.insert(file.to_owned(), None);
    let workflow = resolve_workflow_file(root, &root.join(file))
        .ok()?
        .definition;
    let mut paths = Vec::new();
    for id in &workflow.presentation_order {
        let step = &workflow.steps[id];
        match step {
            ValidatedStep::Workflow(stage) => {
                let nested = child_execution_root_steps(root, &stage.workflow, files)?;
                paths.extend(nested.into_iter().map(|path| format!("{id}.{path}")));
            }
            ValidatedStep::Command(_) | ValidatedStep::Agent(_) => {
                if step.common().workspace == StepWorkspace::Starting {
                    paths.push(id.clone());
                }
            }
        }
    }
    files.insert(file.to_owned(), Some(paths.clone()));
    Some(paths)
}

/// Project immutable run values by the replacement declaration, without borrowing
/// undeclared values into the attempt. The caller must still admit the projected
/// values against every constraint of the resolved replacement definition.
pub(crate) fn project_inputs(
    workflow: &ValidatedWorkflow,
    prior: &ValidatedWorkflow,
    values: &ResolvedInputs,
) -> Result<ResolvedInputs, Vec<String>> {
    let (projected, unsatisfied) = project_input_candidates(workflow, prior, values);
    if unsatisfied.is_empty() {
        Ok(projected)
    } else {
        Err(unsatisfied)
    }
}

pub(crate) fn project_input_candidates(
    workflow: &ValidatedWorkflow,
    prior: &ValidatedWorkflow,
    values: &ResolvedInputs,
) -> (ResolvedInputs, Vec<String>) {
    let mut projected = BTreeMap::new();
    let mut unsatisfied = Vec::new();
    for (name, kind) in &workflow.declared_inputs {
        let retained = values.get(name);
        if retained.is_none() && workflow.input_may_be_omitted(name) {
            // Admission completes an optional or defaulted input the run does not have, as
            // Cloud's continuation planner leaves it to, and `PendingLocalContinuation::begin`
            // expects this projection completed the same way.
            continue;
        }
        if prior.declared_inputs.get(name) != Some(kind)
            || !matches!(
                (kind, retained),
                (WorkflowValueType::Text, Some(ResolvedInput::Text(_)))
                    | (WorkflowValueType::Json, Some(ResolvedInput::Json(_)))
                    | (WorkflowValueType::File, Some(ResolvedInput::File(_)))
                    | (
                        WorkflowValueType::AttachmentCollection,
                        Some(ResolvedInput::Attachments(_))
                    )
            )
        {
            unsatisfied.push(name.clone());
        } else if let Some(value) = retained {
            projected.insert(name.clone(), value.clone());
        }
    }
    (ResolvedInputs::new(projected), unsatisfied)
}

/// Collect independent node and ordinary-output definition failures. Inputs and
/// finalizer-to-finalizer references belong to their own admission domains.
pub(crate) fn check_inheritance(
    workflow: &ValidatedWorkflow,
    previous: &ValidatedWorkflow,
    partition: &Partition,
    states: &BTreeMap<String, PriorState>,
    effectively_skipped: &BTreeSet<String>,
) -> Vec<AdmissionViolation> {
    let inherited = partition
        .inherited
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for id in &partition.inherited {
        let prior = states.get(id).copied();
        if !matches!(
            prior,
            Some(PriorState::Succeeded | PriorState::Skipped | PriorState::Inherited)
        ) {
            violations.push(AdmissionViolation::Node {
                id: id.clone(),
                prior,
            });
        }
    }
    let references = ordered_references(
        workflow,
        referenced_outputs(
            workflow,
            partition.reexecuted.iter().chain(&partition.revalidated),
        ),
    );
    for id in partition.reexecuted.iter().chain(&partition.revalidated) {
        if let Some(step) = workflow.steps.get(id)
            && step.common().failure_policy == FailurePolicy::Required
        {
            // A single reference is unsatisfied when its producer was inherited skipped, and a
            // `firstOf` only when every source was; otherwise the step chooses when it starts.
            let mut producers = BTreeSet::new();
            visit_body_references(step, &mut |sources| {
                if sources.iter().all(|source| {
                    inherited.contains(source.node.id.as_str())
                        && effectively_skipped.contains(&source.node.id)
                }) {
                    producers.extend(sources.iter().map(|source| source.node.id.clone()));
                }
            });
            for producer in producers {
                violations.push(AdmissionViolation::RequiredSkipped {
                    consumer: id.clone(),
                    producer,
                });
            }
        }
    }
    for source in references {
        if source.node.role != WorkflowNodeRole::Step
            || !inherited.contains(source.node.id.as_str())
        {
            continue;
        }
        let expected = workflow
            .steps
            .get(&source.node.id)
            .and_then(|step| step.common().outputs.get(&source.output));
        let prior = previous
            .steps
            .get(&source.node.id)
            .and_then(|step| step.common().outputs.get(&source.output));
        if !matches!((expected, prior), (Some(expected), Some(prior)) if same_output_contract(&expected.definition, &prior.definition))
        {
            violations.push(AdmissionViolation::Reference {
                reference: source.reference(),
            });
        }
    }
    violations
}

fn ordered_references(
    workflow: &ValidatedWorkflow,
    references: BTreeSet<ResolvedOutputSource>,
) -> Vec<ResolvedOutputSource> {
    let indices = workflow
        .presentation_order
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut references = references.into_iter().collect::<Vec<_>>();
    references.sort_by_key(|source| {
        (
            indices
                .get(source.node.id.as_str())
                .copied()
                .unwrap_or(usize::MAX),
            source.reference(),
        )
    });
    references
}

pub(crate) fn sort_violations(violations: &mut [AdmissionViolation], workflow: &ValidatedWorkflow) {
    let indices = workflow
        .presentation_order
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    violations.sort_by_key(|violation| {
        let (reason, node, reference) = match violation {
            AdmissionViolation::InvalidFrom { id } => (0, id.as_str(), id.as_str()),
            AdmissionViolation::Node { id, .. } => (1, id.as_str(), ""),
            AdmissionViolation::RequiredSkipped { consumer, producer } => {
                (1, consumer.as_str(), producer.as_str())
            }
            AdmissionViolation::Reference { reference } => (
                2,
                reference.split('.').nth(1).unwrap_or(""),
                reference.as_str(),
            ),
            AdmissionViolation::HandoverExecutionRootRequired { id, .. } => (3, id.as_str(), ""),
        };
        (
            reason,
            indices.get(node).copied().unwrap_or(usize::MAX),
            reference.to_owned(),
        )
    });
}

pub(crate) fn referenced_outputs<'a>(
    workflow: &ValidatedWorkflow,
    reexecuted: impl IntoIterator<Item = &'a String>,
) -> BTreeSet<ResolvedOutputSource> {
    let mut references = BTreeSet::new();
    for id in reexecuted {
        if let Some(step) = workflow.steps.get(id) {
            check_step_references(step, &mut references);
        }
    }
    for finalizer in workflow.finalizers.values() {
        check_step_references(&finalizer.body, &mut references);
    }
    // Every source of an export and of the outcome, so that an inherited one's value is
    // loaded whichever the export or the outcome settles on.
    references.extend(
        workflow
            .exports
            .values()
            .chain(workflow.outcome.as_ref().map(|outcome| &outcome.source))
            .flat_map(|sources| sources.iter())
            .cloned(),
    );
    references
}

fn check_step_references(step: &ValidatedStep, references: &mut BTreeSet<ResolvedOutputSource>) {
    for source in step.common().condition_values.values() {
        add_reference(source, references);
    }
    check_body_references(step, references);
}

fn check_body_references(step: &ValidatedStep, references: &mut BTreeSet<ResolvedOutputSource>) {
    visit_body_references(step, &mut |sources| {
        references.extend(sources.iter().cloned())
    });
}

/// Visit each output reference of a step's body as the sources it may take: one for a single
/// reference, a `firstOf`'s list in written order, and none for a value that names no
/// output.
fn visit_body_references(step: &ValidatedStep, visit: &mut impl FnMut(&[ResolvedOutputSource])) {
    match step {
        ValidatedStep::Command(command) => {
            for reference in command.inputs.values() {
                visit(reference.source.output_sources());
            }
        }
        ValidatedStep::Workflow(workflow) => {
            for input in workflow.inputs.values() {
                visit(input.reference.source.output_sources());
            }
            if let Some(for_each) = &workflow.for_each {
                visit(for_each.items.source.output_sources());
            }
            for target in workflow.edges.values() {
                add_rule_references(target, visit);
            }
        }
        ValidatedStep::Agent(agent) => {
            // Document validation and resolved-reference admission traverse distinct types.
            // Keeping these traversals separate makes the admission boundary explicit.
            for source in agent
                .agent
                .message
                .text
                .iter()
                .chain(&agent.agent.message.attachments)
            {
                if let ValidatedMessageSource::Reference { source, .. } = source {
                    visit(source.output_sources());
                }
            }
        }
    }
}

/// The `outputs.<step>.<output>` operands of an `external` wait's rule, which the wait record
/// resolves to literals when the step enters it, so an inherited producer's value is loaded
/// for the attempt.
fn add_rule_references(
    target: &ValidatedEdgeTarget,
    visit: &mut impl FnMut(&[ResolvedOutputSource]),
) {
    match target {
        ValidatedEdgeTarget::Wait {
            rule: Some(rule), ..
        } => {
            for operand in parse_where(&rule.where_)
                .iter()
                .flatten()
                .flat_map(|(left, right)| [left, right])
            {
                if let Operand::Outputs { step, output } = operand {
                    visit(&[ResolvedOutputSource {
                        node: WorkflowNode {
                            id: step.clone(),
                            role: WorkflowNodeRole::Step,
                        },
                        output: output.clone(),
                        value_type: WorkflowValueType::Text,
                    }]);
                }
            }
        }
        ValidatedEdgeTarget::Limited { else_, .. }
        | ValidatedEdgeTarget::HostWait { else_, .. } => add_rule_references(else_, visit),
        ValidatedEdgeTarget::Wait { rule: None, .. }
        | ValidatedEdgeTarget::Step(_)
        | ValidatedEdgeTarget::Exit(_) => {}
    }
}

fn add_reference(source: &ResolvedValueSource, references: &mut BTreeSet<ResolvedOutputSource>) {
    references.extend(source.output_sources().iter().cloned());
}

/// Compare resolved node semantics and only the retained static bytes reachable
/// from this node. A change elsewhere in the closure does not change this node.
pub(crate) fn definition_changed(
    current: &ResolvedWorkflow,
    previous: &ResolvedWorkflow,
    id: &str,
) -> bool {
    let current_step = current.definition.steps.get(id);
    let previous_step = previous.definition.steps.get(id);
    if current_step != previous_step
        || current.definition.recoveries.get(id) != previous.definition.recoveries.get(id)
    {
        return true;
    }
    let Some(step) = current_step else {
        return true;
    };
    let mut paths = BTreeSet::new();
    let common = step.common();
    for output in common.outputs.values() {
        match &output.definition {
            Output::JsonPath { schema, .. } | Output::JsonAgentResult { schema } => {
                paths.insert(schema.as_str());
            }
            _ => {}
        }
    }
    if let Some(Some(super::validated::ValidatedStepRecovery {
        handler: Some(super::validated::ValidatedRecoveryHandler::Agent { prompt, .. }),
        ..
    })) = current.definition.recoveries.get(id)
    {
        paths.insert(prompt.as_str());
    }
    if let ValidatedStep::Workflow(workflow) = step {
        paths.extend(workflow.child_paths.iter().map(String::as_str));
    }
    if let ValidatedStep::Agent(agent) = step {
        paths.insert(agent.agent.system_prompt.as_str());
        for source in agent
            .agent
            .message
            .text
            .iter()
            .chain(&agent.agent.message.attachments)
        {
            if let ValidatedMessageSource::File { path } = source {
                paths.insert(path);
            }
        }
    }
    paths
        .into_iter()
        .any(|path| current.source_bytes(path) != previous.source_bytes(path))
}

fn same_output_contract(current: &Output, previous: &Output) -> bool {
    match (current, previous) {
        (
            Output::TextPath { .. } | Output::TextAgentResponse,
            Output::TextPath { .. } | Output::TextAgentResponse,
        )
        | (
            Output::JsonPath { .. } | Output::JsonAgentResult { .. },
            Output::JsonPath { .. } | Output::JsonAgentResult { .. },
        )
        | (Output::GitBranchWorkspace, Output::GitBranchWorkspace)
        | (Output::ChildOutcome, Output::ChildOutcome) => true,
        (Output::FilePath { media_type: a, .. }, Output::FilePath { media_type: b, .. }) => a == b,
        (Output::ChildExport { value_type: a }, Output::ChildExport { value_type: b }) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKSPACE_STEPS: &str = r#"schemaVersion: 1
steps:
  candidate: {kind: cmd, workspace: new, command: {argv: ["true"]}}
  checkBase: {kind: cmd, workspace: read, dependsOn: [candidate], command: {argv: ["true"]}}
  edit: {kind: cmd, dependsOn: [checkBase], command: {argv: ["true"]}}
  checkEdit: {kind: cmd, workspace: read, dependsOn: [edit], command: {argv: ["true"]}}
  publish: {kind: cmd, dependsOn: [checkEdit], command: {argv: ["true"]}}
"#;

    #[test]
    fn partition_revalidates_dependents_whose_recorded_result_may_apply() {
        let select = |steps: &str, from: &str, lost: &[&str], unfit: Option<&str>| {
            let workflow =
                super::super::validation::validate(super::super::decode(steps.as_bytes()).unwrap())
                    .unwrap();
            let reusable = workflow
                .steps
                .keys()
                .filter(|id| Some(id.as_str()) != unfit)
                .cloned()
                .collect();
            let lost = lost.iter().map(|id| (*id).to_owned()).collect();
            partition(
                &workflow,
                &[from.to_owned()],
                &BTreeSet::new(),
                &lost,
                &reusable,
            )
            .unwrap()
        };
        let selected = select(WORKSPACE_STEPS, "publish", &["candidate"], None);
        assert_eq!(
            selected.reexecuted,
            ["candidate", "edit", "checkEdit", "publish"]
        );
        assert_eq!(selected.revalidated, ["checkBase"]);
        assert_eq!(selected.rebuilt, ["candidate"]);
        let unfit = select(
            WORKSPACE_STEPS,
            "publish",
            &["candidate"],
            Some("checkBase"),
        );
        assert!(unfit.revalidated.is_empty());
        assert!(unfit.reexecuted.iter().any(|id| id == "checkBase"));

        let steps = r#"schemaVersion: 1
steps:
  plan:
    kind: cmd
    command: {argv: ["true"]}
    outputs: {value: {kind: text, from: path, path: value.txt}}
  notify: {kind: cmd, workspace: none, inputs: {v: {ref: outputs.plan.value}}, command: {argv: ["true"]}}
  candidate: {kind: cmd, workspace: new, inputs: {v: {ref: outputs.plan.value}}, command: {argv: ["true"]}}
  edit: {kind: cmd, dependsOn: [candidate], command: {argv: ["true"]}}
  inspect: {kind: cmd, workspace: none, condition: {disposition: {node: plan, is: succeeded}}, command: {argv: ["true"]}}
"#;
        let selected = select(steps, "plan", &[], None);
        assert_eq!(selected.reexecuted, ["plan", "inspect"]);
        assert_eq!(selected.revalidated, ["notify", "candidate", "edit"]);

        let unmarked = WORKSPACE_STEPS
            .replace("workspace: new, ", "")
            .replace("workspace: read, ", "");
        for id in ["candidate", "checkBase", "edit", "checkEdit", "publish"] {
            assert!(
                select(&unmarked, id, &[], None).revalidated.is_empty(),
                "{id}"
            );
        }
    }

    // SC-HANDOVER-1, SC-HANDOVER-7
    #[test]
    fn handover_judges_the_resolved_workspaces_of_steps_the_attempt_can_run() {
        let judge = |steps: &str, lost: &[&str]| {
            let workflow =
                super::super::validation::validate(super::super::decode(steps.as_bytes()).unwrap())
                    .unwrap();
            let selected = partition(
                &workflow,
                &["test".to_owned()],
                &BTreeSet::new(),
                &lost.iter().map(|id| (*id).to_owned()).collect(),
                &BTreeSet::new(),
            )
            .unwrap();
            handover_violations(&workflow, &[selected], None)
        };
        let rebuilt = r#"schemaVersion: 1
steps:
  checkout: {kind: cmd, workspace: new, command: {argv: ["true"]}}
  edit: {kind: cmd, dependsOn: [checkout], command: {argv: ["true"]}}
  test: {kind: cmd, dependsOn: [edit], command: {argv: ["true"]}}
"#;
        assert!(judge(rebuilt, &["checkout"]).is_empty());

        let starting = r#"schemaVersion: 1
steps:
  prepare: {kind: cmd, command: {argv: ["true"]}}
  test: {kind: cmd, dependsOn: [prepare], command: {argv: ["true"]}}
"#;
        assert_eq!(
            judge(starting, &[]),
            [AdmissionViolation::HandoverExecutionRootRequired {
                id: "test".to_owned(),
                child: None,
            }]
        );
        let none = starting.replace("dependsOn:", "workspace: none, dependsOn:");
        assert!(judge(&none, &[]).is_empty());
    }

    // SC-HANDOVER-1, SC-HANDOVER-7
    #[test]
    fn handover_judges_children_reached_by_a_backward_edge() {
        let copy = tempfile::tempdir().unwrap();
        let root = copy.path();
        std::fs::write(
            root.join("root.yaml"),
            r#"schemaVersion: 1
steps:
  design: {kind: workflow, workflow: design.yaml, on: {succeeded: build, failed: exit.failed}}
  build: {kind: workflow, workflow: build.yaml, on: {succeeded: exit.succeeded, failed: design}}
"#,
        )
        .unwrap();
        let child = r#"schemaVersion: 1
steps:
  prepare: {kind: cmd, command: {argv: ["true"]}}
"#;
        std::fs::write(root.join("design.yaml"), child).unwrap();
        std::fs::write(
            root.join("build.yaml"),
            child.replace("kind: cmd", "kind: cmd, workspace: new"),
        )
        .unwrap();
        let workflow =
            super::super::resolution::resolve_workflow_file(root, &root.join("root.yaml"))
                .unwrap()
                .definition;
        let selected = partition(
            &workflow,
            &["build".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.inherited, ["design"]);
        assert_eq!(
            handover_violations(&workflow, &[selected], Some(root)),
            [AdmissionViolation::HandoverExecutionRootRequired {
                id: "design".to_owned(),
                child: Some("prepare".to_owned()),
            }]
        );
    }

    #[tokio::test]
    async fn a_release_wait_is_judged_from_its_hand_back_step_as_well_as_then() {
        let copy = tempfile::tempdir().unwrap();
        let root = copy.path();
        std::fs::write(
            root.join("root.yaml"),
            r#"schemaVersion: 1
steps:
  fix: {kind: workflow, workflow: fix.yaml, on: {succeeded: review, failed: exit.failed}}
  review: {kind: workflow, workflow: rebuilt.yaml, on: {succeeded: {wait: approval, runner: release, then: merge, onHandBack: fix}, failed: exit.failed}}
  merge: {kind: workflow, workflow: rebuilt.yaml, on: {succeeded: exit.succeeded, failed: exit.failed}}
"#,
        )
        .unwrap();
        let child = r#"schemaVersion: 1
steps:
  prepare: {kind: cmd, command: {argv: ["true"]}}
"#;
        std::fs::write(root.join("fix.yaml"), child).unwrap();
        std::fs::write(
            root.join("rebuilt.yaml"),
            child.replace("kind: cmd", "kind: cmd, workspace: new"),
        )
        .unwrap();
        let workflow = resolve_workflow_file(root, &root.join("root.yaml")).unwrap();
        // `fix` and `review` succeeded before the wait, so only a hand-back runs `fix` again.
        let steps = BTreeMap::from([("merge".to_owned(), StepState::<()>::Pending)]);
        let mut wait = WaitRecord {
            kind: super::super::document::WaitKind::Approval,
            since: "2026-11-08T08:00:00Z".to_owned(),
            step: vec![serde_json::Value::String("review".to_owned())],
            then: "merge".to_owned(),
            on_hand_back: None,
            rule: super::super::wait::derive_rule(super::super::document::WaitKind::Approval, true)
                .unwrap(),
            payload: serde_json::Map::new(),
            release: None,
        };
        assert_eq!(
            wait_release(&workflow, &wait, &steps, root.to_owned())
                .await
                .unwrap(),
            WaitRelease {
                permitted: true,
                execution_root_steps: None,
            }
        );
        wait.on_hand_back = Some("fix".to_owned());
        assert_eq!(
            wait_release(&workflow, &wait, &steps, root.to_owned())
                .await
                .unwrap(),
            WaitRelease {
                permitted: false,
                execution_root_steps: Some(vec![ExecutionRootStep {
                    id: "fix".to_owned(),
                    child: Some("prepare".to_owned()),
                }]),
            }
        );
    }

    #[test]
    fn a_lost_workspace_reexecutes_its_establishing_step_and_dependents() {
        let steps = WORKSPACE_STEPS;
        let select = |steps: &str, from: &str, lost: &[&str]| {
            let workflow =
                super::super::validation::validate(super::super::decode(steps.as_bytes()).unwrap())
                    .unwrap();
            let lost = lost.iter().map(|id| (*id).to_owned()).collect();
            partition(
                &workflow,
                &[from.to_owned()],
                &BTreeSet::new(),
                &lost,
                &BTreeSet::new(),
            )
            .unwrap()
        };
        let rebuilt = select(steps, "publish", &["candidate"]);
        assert_eq!(
            rebuilt.reexecuted,
            ["candidate", "checkBase", "edit", "checkEdit", "publish"]
        );
        assert!(rebuilt.inherited.is_empty());
        assert_eq!(rebuilt.rebuilt, ["candidate"]);

        let kept = select(steps, "publish", &[]);
        assert_eq!(kept.reexecuted, ["publish"]);
        assert!(kept.rebuilt.is_empty());
        assert!(
            select(steps, "candidate", &["candidate"])
                .rebuilt
                .is_empty()
        );

        let branches = format!(
            "{steps}{}",
            r#"  notify: {kind: cmd, workspace: none, dependsOn: [candidate], command: {argv: ["true"]}}
  other: {kind: cmd, workspace: new, command: {argv: ["true"]}}
  otherTail: {kind: cmd, dependsOn: [other], command: {argv: ["true"]}}
"#
        );
        let notify = select(&branches, "notify", &["candidate"]);
        assert_eq!(notify.reexecuted, ["notify"]);
        assert!(notify.rebuilt.is_empty());
        let publish = select(&branches, "publish", &["candidate", "other"]);
        assert_eq!(publish.inherited, ["other", "otherTail"]);
        assert_eq!(publish.rebuilt, ["candidate"]);
    }

    #[test]
    fn an_optional_or_defaulted_input_the_run_lacks_is_left_to_admission_to_complete() {
        let validated = |inputs: &str| {
            let document = super::super::decode(
                format!(
                    "schemaVersion: 1\ninputs:\n{inputs}steps:\n  work:\n    kind: cmd\n    command: {{argv: [\"true\"]}}\n"
                )
                .as_bytes(),
            )
            .unwrap();
            super::super::validation::validate(document).unwrap()
        };
        let prior = validated("  ticket: {kind: text}\n");
        let values = ResolvedInputs::new(BTreeMap::from([(
            "ticket".to_owned(),
            ResolvedInput::Text(std::sync::Arc::from("AUTO-199")),
        )]));

        let widened = validated(
            "  ticket: {kind: text}\n  branch: {kind: text, optional: true}\n  baseBranch: {kind: text, default: main}\n",
        );
        let projected = project_inputs(&widened, &prior, &values).unwrap();
        assert!(projected.get("ticket").is_some());
        assert!(projected.get("branch").is_none());
        assert!(projected.get("baseBranch").is_none());

        let demanding = validated("  ticket: {kind: text}\n  extra: {kind: text}\n");
        assert_eq!(
            project_inputs(&demanding, &prior, &values).unwrap_err(),
            ["extra".to_owned()]
        );
    }

    #[test]
    fn union_of_control_and_data_closures_uses_kahn_order_not_selection_order() {
        let document = super::super::decode(
            b"schemaVersion: 1\nsteps:\n  west:\n    kind: cmd\n    command: {argv: [\"true\"]}\n    outputs:\n      text: {kind: text, from: path, path: west.txt}\n  east:\n    kind: cmd\n    command: {argv: [\"true\"]}\n  join:\n    kind: cmd\n    dependsOn: [east]\n    inputs:\n      value: {ref: outputs.west.text}\n    command: {argv: [\"true\"]}\n  tail:\n    kind: cmd\n    dependsOn: [join]\n    command: {argv: [\"true\"]}\n  alone:\n    kind: cmd\n    command: {argv: [\"true\"]}\nfinalizers:\n  cleanup:\n    kind: cmd\n    command: {argv: [\"true\"]}\n",
        )
        .unwrap();
        let workflow = super::super::validation::validate(document).unwrap();
        let from = ["east".to_owned(), "west".to_owned()];
        let selected = partition(
            &workflow,
            &from,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["west", "east", "join", "tail"]);
        assert_eq!(selected.inherited, ["alone"]);
        assert_eq!(
            partition(
                &workflow,
                &["cleanup".to_owned()],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new()
            ),
            Err(vec!["cleanup".to_owned()])
        );
        assert_eq!(
            partition(
                &workflow,
                &["east".to_owned(), "east".to_owned()],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new()
            ),
            Err(vec!["east".to_owned()])
        );
    }

    #[test]
    fn an_edge_scheduled_resume_reexecutes_the_steps_its_edges_reach() {
        let document = super::super::decode(
            b"schemaVersion: 1\noutcomes: [landed, failed]\nsteps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    on:\n      planned: build\n      blocked: exit.failed\n  build:\n    kind: workflow\n    workflow: build.yaml\n    on:\n      built:\n        wait: approval\n        then: review\n        onHandBack: fix\n      failed: exit.failed\n  review:\n    kind: workflow\n    workflow: review.yaml\n    on:\n      approve: exit.landed\n  fix:\n    kind: workflow\n    workflow: fix.yaml\n    on:\n      fixed: exit.landed\n",
        )
        .unwrap();
        let child = |outcomes: &[&str]| super::super::validation::ChildWorkflowSummary {
            outcomes: outcomes
                .iter()
                .map(|outcome| (*outcome).to_owned())
                .collect(),
            exports: BTreeMap::new(),
            inputs: BTreeMap::new(),
            nesting: super::super::validation::ChildNesting::Stage,
            has_root_blocks: false,
            paths: BTreeSet::new(),
        };
        let children = BTreeMap::from([
            ("design.yaml".to_owned(), child(&["planned", "blocked"])),
            ("build.yaml".to_owned(), child(&["built", "failed"])),
            ("review.yaml".to_owned(), child(&["approve"])),
            ("fix.yaml".to_owned(), child(&["fixed"])),
        ]);
        let workflow =
            super::super::validation::validate_with_children(document, None, &children).unwrap();

        // A wait's `then` and its `onHandBack` are both dependents.
        let selected = partition(
            &workflow,
            &["build".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["build", "review", "fix"]);
        assert_eq!(selected.inherited, ["design"]);
        let selected = partition(
            &workflow,
            &["design".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["design", "build", "review", "fix"]);
        assert!(selected.inherited.is_empty());
        let selected = partition(
            &workflow,
            &["review".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["review"]);
        assert_eq!(selected.inherited, ["design", "build", "fix"]);
    }

    // An edge-scheduled continuation names one step and also re-executes every step the prior
    // attempt left unfinished, so the walk restarts from the named step.
    #[test]
    fn an_edge_scheduled_continuation_reexecutes_the_unfinished_steps() {
        let document = super::super::decode(
            b"schemaVersion: 1\noutcomes: [landed, failed]\nsteps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    on:\n      planned: review\n      blocked: exit.failed\n  review:\n    kind: workflow\n    workflow: review.yaml\n    on:\n      approve:\n        wait: approval\n        then: merge\n        onHandBack: fix\n  fix:\n    kind: workflow\n    workflow: fix.yaml\n    on:\n      built: merge\n  merge:\n    kind: workflow\n    workflow: merge.yaml\n    on:\n      landed: exit.landed\n",
        )
        .unwrap();
        let child = |outcomes: &[&str]| super::super::validation::ChildWorkflowSummary {
            outcomes: outcomes
                .iter()
                .map(|outcome| (*outcome).to_owned())
                .collect(),
            exports: BTreeMap::new(),
            inputs: BTreeMap::new(),
            nesting: super::super::validation::ChildNesting::Stage,
            has_root_blocks: false,
            paths: BTreeSet::new(),
        };
        let children = BTreeMap::from([
            ("design.yaml".to_owned(), child(&["planned", "blocked"])),
            ("review.yaml".to_owned(), child(&["approve"])),
            ("fix.yaml".to_owned(), child(&["built"])),
            ("merge.yaml".to_owned(), child(&["landed"])),
        ]);
        let workflow =
            super::super::validation::validate_with_children(document, None, &children).unwrap();
        // The prior attempt waited on `review`'s approval: `fix` and `merge` were not reached.
        let unfinished = BTreeSet::from(["fix".to_owned(), "merge".to_owned()]);

        let selected = partition(
            &workflow,
            &["merge".to_owned()],
            &unfinished,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["fix", "merge"]);
        assert_eq!(selected.inherited, ["design", "review"]);
        assert_eq!(
            partition(
                &workflow,
                &["fix".to_owned(), "merge".to_owned()],
                &unfinished,
                &BTreeSet::new(),
                &BTreeSet::new()
            ),
            Err(vec!["merge".to_owned()])
        );
    }

    // A backward edge adds no dependent, so the producer a continued step reads through an
    // output reference stays inherited, while a limited edge's forward `then` is one.
    #[test]
    fn an_edge_continuation_reexecutes_only_forward_targets() {
        let document = super::super::decode(
            b"schemaVersion: 1\noutcomes: [landed, failed]\nsteps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    on:\n      planned: review\n  review:\n    kind: workflow\n    workflow: review.yaml\n    on:\n      proceed: merge\n      hand_back:\n        then: fix\n        limit: 2\n        else:\n          wait: repair\n          then: review\n  fix:\n    kind: workflow\n    workflow: build.yaml\n    inputs:\n      findings: {ref: outputs.review.findings}\n    on:\n      built: review\n  merge:\n    kind: workflow\n    workflow: merge.yaml\n    on:\n      landed: exit.landed\n",
        )
        .unwrap();
        let child = |outcomes: &[&str], exports: &[&str], inputs: &[&str]| {
            super::super::validation::ChildWorkflowSummary {
                outcomes: outcomes
                    .iter()
                    .map(|outcome| (*outcome).to_owned())
                    .collect(),
                exports: exports
                    .iter()
                    .map(|export| ((*export).to_owned(), WorkflowValueType::Text))
                    .collect(),
                inputs: inputs
                    .iter()
                    .map(|input| ((*input).to_owned(), (WorkflowValueType::Text, true)))
                    .collect(),
                nesting: super::super::validation::ChildNesting::Stage,
                has_root_blocks: false,
                paths: BTreeSet::new(),
            }
        };
        let children = BTreeMap::from([
            ("design.yaml".to_owned(), child(&["planned"], &[], &[])),
            (
                "review.yaml".to_owned(),
                child(&["proceed", "hand_back"], &["findings"], &[]),
            ),
            (
                "build.yaml".to_owned(),
                child(&["built"], &[], &["findings"]),
            ),
            ("merge.yaml".to_owned(), child(&["landed"], &[], &[])),
        ]);
        let workflow =
            super::super::validation::validate_with_children(document, None, &children).unwrap();

        // `review` handed back: `fix` and `merge` were not reached.
        let unfinished = BTreeSet::from(["fix".to_owned(), "merge".to_owned()]);
        let selected = partition(
            &workflow,
            &["fix".to_owned()],
            &unfinished,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["fix", "merge"]);
        assert_eq!(selected.inherited, ["design", "review"]);

        // `fix` built and its backward edge continues at `review`.
        let unfinished = BTreeSet::from(["merge".to_owned()]);
        let selected = partition(
            &workflow,
            &["review".to_owned()],
            &unfinished,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.reexecuted, ["review", "fix", "merge"]);
        assert_eq!(selected.inherited, ["design"]);
    }

    // A step or export that reads an inherited `workflow` step's child export or
    // `outcome` keeps its contract, so the step stays inherited.
    #[test]
    fn an_inherited_workflow_steps_child_exports_and_outcome_keep_their_contract() {
        let document = super::super::decode(
            b"schemaVersion: 1\noutcomes: [landed, failed]\nsteps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    on:\n      planned: build\n      blocked: exit.failed\n  build:\n    kind: workflow\n    workflow: build.yaml\n    inputs:\n      parts: {ref: outputs.design.parts}\n      verdict: {ref: outputs.design.outcome}\n    on:\n      built: exit.landed\nexports:\n  parts: {ref: outputs.design.parts}\n  verdict: {ref: outputs.design.outcome}\n",
        )
        .unwrap();
        let summary = super::super::validation::ChildWorkflowSummary {
            outcomes: vec!["planned".to_owned(), "blocked".to_owned()],
            exports: BTreeMap::from([("parts".to_owned(), WorkflowValueType::Json)]),
            inputs: BTreeMap::new(),
            nesting: super::super::validation::ChildNesting::Stage,
            has_root_blocks: false,
            paths: BTreeSet::new(),
        };
        let children = BTreeMap::from([
            ("design.yaml".to_owned(), summary.clone()),
            (
                "build.yaml".to_owned(),
                super::super::validation::ChildWorkflowSummary {
                    outcomes: vec!["built".to_owned()],
                    exports: BTreeMap::new(),
                    inputs: BTreeMap::from([
                        ("parts".to_owned(), (WorkflowValueType::Json, false)),
                        ("verdict".to_owned(), (WorkflowValueType::Text, false)),
                    ]),
                    ..summary
                },
            ),
        ]);
        let workflow =
            super::super::validation::validate_with_children(document, None, &children).unwrap();
        let selected = partition(
            &workflow,
            &["build".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(selected.inherited, ["design"]);
        let states = BTreeMap::from([("design".to_owned(), PriorState::Succeeded)]);
        assert!(
            check_inheritance(&workflow, &workflow, &selected, &states, &BTreeSet::new())
                .is_empty()
        );

        let mut previous = workflow.clone();
        if let Some(ValidatedStep::Workflow(design)) = previous.steps.get_mut("design") {
            design.common.outputs.get_mut("parts").unwrap().definition = Output::ChildExport {
                value_type: WorkflowValueType::Text,
            };
        }
        let violations =
            check_inheritance(&workflow, &previous, &selected, &states, &BTreeSet::new());
        assert!(!violations.is_empty());
        assert!(violations.iter().all(|violation| matches!(
            violation,
            AdmissionViolation::Reference { reference } if reference == "outputs.design.parts"
        )));
    }

    #[test]
    fn reference_failures_follow_presentation_order_not_lexical_ids() {
        let document = super::super::decode(b"schemaVersion: 1\nsteps:\n  zeta:\n    kind: cmd\n    outputs:\n      value: {kind: text, from: path, path: z.txt}\n    command: {argv: [\"true\"]}\n  alpha:\n    kind: cmd\n    outputs:\n      value: {kind: text, from: path, path: a.txt}\n    command: {argv: [\"true\"]}\n  consume:\n    kind: cmd\n    inputs:\n      z: {ref: outputs.zeta.value}\n      a: {ref: outputs.alpha.value}\n    command: {argv: [\"true\"]}\n").unwrap();
        let workflow = super::super::validation::validate(document).unwrap();
        let selected = partition(
            &workflow,
            &["consume".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        let mut previous = workflow.clone();
        for id in ["zeta", "alpha"] {
            if let Some(ValidatedStep::Command(command)) = previous.steps.get_mut(id) {
                command.common.outputs.clear();
            }
        }
        let states = BTreeMap::from([
            ("zeta".to_owned(), PriorState::Succeeded),
            ("alpha".to_owned(), PriorState::Succeeded),
        ]);
        assert_eq!(
            check_inheritance(&workflow, &previous, &selected, &states, &BTreeSet::new()),
            vec![
                AdmissionViolation::Reference {
                    reference: "outputs.zeta.value".to_owned()
                },
                AdmissionViolation::Reference {
                    reference: "outputs.alpha.value".to_owned()
                },
            ]
        );
    }

    // An inherited `workflow` step's definition covers the bytes its child resolution
    // reached, the child file and its schemas, and no others.
    #[test]
    fn definition_comparison_covers_the_bytes_a_workflow_steps_child_reached() {
        use std::fs;
        use std::path::Path;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("workflow.yaml"), "schemaVersion: 1\noutcomes: [landed, failed]\nsteps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    on:\n      succeeded: build\n      failed: exit.failed\n  build:\n    kind: workflow\n    workflow: build.yaml\n    on:\n      succeeded: exit.landed\n      failed: exit.failed\n").unwrap();
        let child = |name: &str, argv: &str| {
            format!(
                "schemaVersion: 1\nsteps:\n  work:\n    kind: cmd\n    command: {{argv: [\"{argv}\"]}}\n    outputs:\n      result: {{kind: json, from: path, path: result.json, schema: {name}.schema.json}}\n"
            )
        };
        let schema = |kind: &str| {
            format!(
                r#"{{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"{kind}"}}"#
            )
        };
        for name in ["design", "build"] {
            fs::write(root.join(format!("{name}.yaml")), child(name, "true")).unwrap();
            fs::write(root.join(format!("{name}.schema.json")), schema("object")).unwrap();
        }
        let resolve =
            || super::super::resolution::resolve(root, Path::new("workflow.yaml")).unwrap();
        let previous = resolve();

        let edits = [
            (
                "design.yaml",
                child("design", "false"),
                child("design", "true"),
            ),
            ("design.schema.json", schema("string"), schema("object")),
        ];
        for (file, edited, original) in edits {
            fs::write(root.join(file), edited).unwrap();
            let current = resolve();
            assert!(definition_changed(&current, &previous, "design"), "{file}");
            assert!(!definition_changed(&current, &previous, "build"), "{file}");
            fs::write(root.join(file), original).unwrap();
        }

        let current = resolve();
        assert!(!definition_changed(&current, &previous, "design"));
        assert!(!definition_changed(&current, &previous, "build"));
    }

    #[test]
    fn definition_comparison_tracks_only_node_reached_static_bytes() {
        use std::fs;
        use std::path::Path;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("flow.yaml"), "schemaVersion: 1\nsteps:\n  cached:\n    kind: cmd\n    command: {argv: [\"true\"]}\n    outputs:\n      result: {kind: json, from: path, path: result.json, schema: result.schema.json}\n  independent:\n    kind: cmd\n    command: {argv: [\"true\"]}\n").unwrap();
        fs::write(
            root.join("result.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .unwrap();
        let previous = super::super::resolution::resolve(root, Path::new("flow.yaml")).unwrap();
        fs::write(
            root.join("result.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string"}"#,
        )
        .unwrap();
        let current = super::super::resolution::resolve(root, Path::new("flow.yaml")).unwrap();
        assert!(definition_changed(&current, &previous, "cached"));
        assert!(!definition_changed(&current, &previous, "independent"));
    }

    #[test]
    fn definition_comparison_includes_agent_and_recovery_prompt_bytes() {
        use std::fs;
        use std::path::Path;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("system.md"), "initial system").unwrap();
        fs::write(root.join("message.md"), "initial message").unwrap();
        fs::write(root.join("repair.md"), "initial repair").unwrap();
        fs::write(root.join("flow.yaml"), "schemaVersion: 1\nagentProfiles:\n  coding:\n    harness:\n      kind: pi\n      config: {model: fixture/model, thinking: off}\nsteps:\n  cached:\n    kind: agent\n    recovery:\n      retries: 1\n      handler:\n        kind: agent\n        profile: coding\n        prompt: repair.md\n    agent:\n      profile: coding\n      systemPrompt: system.md\n      message:\n        text: [{file: message.md}]\n").unwrap();
        let previous = super::super::resolution::resolve(root, Path::new("flow.yaml")).unwrap();
        for (file, bytes) in [("system.md", "new system"), ("repair.md", "new repair")] {
            fs::write(root.join(file), bytes).unwrap();
            let current = super::super::resolution::resolve(root, Path::new("flow.yaml")).unwrap();
            assert!(definition_changed(&current, &previous, "cached"), "{file}");
            fs::write(
                root.join(file),
                format!("initial {name}", name = file.trim_end_matches(".md")),
            )
            .unwrap();
        }
    }

    #[test]
    fn changed_retained_json_schema_is_recorded_without_rejecting_inheritance() {
        use std::{fs, path::Path};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("flow.yaml"), "schemaVersion: 1\nsteps:\n  producer:\n    kind: cmd\n    command: {argv: [\"true\"]}\n    outputs:\n      value: {kind: json, from: path, path: value.json, schema: value.schema.json}\n  consumer:\n    kind: cmd\n    inputs:\n      value: {ref: outputs.producer.value}\n    command: {argv: [\"true\"]}\n").unwrap();
        fs::write(
            root.join("value.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .unwrap();
        let previous = super::super::resolution::resolve(root, Path::new("flow.yaml")).unwrap();
        fs::write(
            root.join("value.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string"}"#,
        )
        .unwrap();
        let current = super::super::resolution::resolve(root, Path::new("flow.yaml")).unwrap();
        let selected = partition(
            &current.definition,
            &["consumer".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        let states = BTreeMap::from([("producer".to_owned(), PriorState::Succeeded)]);
        assert!(
            check_inheritance(
                &current.definition,
                &previous.definition,
                &selected,
                &states,
                &BTreeSet::new(),
            )
            .is_empty()
        );
        assert!(definition_changed(&current, &previous, "producer"));
    }

    #[test]
    fn condition_only_skipped_source_remains_admissible_across_inherited_chain() {
        let document = super::super::decode(b"schemaVersion: 1\nsteps:\n  producer:\n    kind: cmd\n    command: {argv: [\"true\"]}\n    outputs:\n      value: {kind: text, from: path, path: value.txt}\n  consumer:\n    kind: cmd\n    condition:\n      equals:\n        - ref: outputs.producer.value\n        - value: expected\n    command: {argv: [\"true\"]}\n").unwrap();
        let workflow = super::super::validation::validate(document).unwrap();
        let selected = partition(
            &workflow,
            &["consumer".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        let states = BTreeMap::from([("producer".to_owned(), PriorState::Inherited)]);
        let skipped = BTreeSet::from(["producer".to_owned()]);
        assert!(check_inheritance(&workflow, &workflow, &selected, &states, &skipped).is_empty());
    }

    #[test]
    fn admission_reports_inherited_node_and_reference_failures_independently() {
        let document = super::super::decode(
            b"schemaVersion: 1\nsteps:\n  cached:\n    kind: cmd\n    outputs:\n      value: {kind: text, from: path, path: value.txt}\n    command: {argv: [\"true\"]}\n  run:\n    kind: cmd\n    inputs:\n      value: {ref: outputs.cached.value}\n    command: {argv: [\"true\"]}\n  stranded:\n    kind: cmd\n    command: {argv: [\"true\"]}\n",
        ).unwrap();
        let workflow = super::super::validation::validate(document).unwrap();
        let selected = partition(
            &workflow,
            &["run".to_owned()],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        let mut previous = workflow.clone();
        if let Some(ValidatedStep::Command(command)) = previous.steps.get_mut("cached") {
            command.common.outputs.clear();
        }
        let states = BTreeMap::from([
            ("cached".to_owned(), PriorState::Inherited),
            ("stranded".to_owned(), PriorState::Unsatisfied),
        ]);
        assert_eq!(
            check_inheritance(&workflow, &previous, &selected, &states, &BTreeSet::new()),
            vec![
                AdmissionViolation::Node {
                    id: "stranded".to_owned(),
                    prior: Some(PriorState::Unsatisfied)
                },
                AdmissionViolation::Reference {
                    reference: "outputs.cached.value".to_owned()
                },
            ]
        );
        let states = BTreeMap::from([
            ("cached".to_owned(), PriorState::Skipped),
            ("stranded".to_owned(), PriorState::Succeeded),
        ]);
        assert!(
            check_inheritance(
                &workflow,
                &workflow,
                &selected,
                &states,
                &BTreeSet::from(["cached".to_owned()]),
            )
            .contains(&AdmissionViolation::RequiredSkipped {
                consumer: "run".to_owned(),
                producer: "cached".to_owned()
            })
        );
    }

    // A `firstOf` refuses a required re-executed consumer only when every source is inherited
    // and was skipped, naming each producer; a source that is re-executed, or inherited and
    // succeeded, admits it, and an advisory consumer is admitted in every case. Every source
    // of a re-executed consumer is a referenced output.
    #[test]
    fn a_first_of_refuses_a_required_consumer_only_when_every_source_was_skipped() {
        let validated = |policy: &str| {
            let document = super::super::decode(format!("schemaVersion: 1\ninputs:\n  branch: {{kind: text}}\nsteps:\n  a:\n    kind: cmd\n    condition: {{equals: [{{ref: inputs.branch}}, {{value: a}}]}}\n    command: {{argv: [\"true\"]}}\n    outputs:\n      result: {{kind: text, from: path, path: a.txt}}\n  b:\n    kind: cmd\n    condition: {{equals: [{{ref: inputs.branch}}, {{value: b}}]}}\n    command: {{argv: [\"true\"]}}\n    outputs:\n      result: {{kind: text, from: path, path: b.txt}}\n  c:\n    kind: cmd\n    failurePolicy: {policy}\n    inputs:\n      result: {{firstOf: [outputs.a.result, outputs.b.result]}}\n    command: {{argv: [\"true\"]}}\n").as_bytes()).unwrap();
            super::super::validation::validate(document).unwrap()
        };
        let source = |id: &str| ResolvedOutputSource {
            node: WorkflowNode {
                id: id.to_owned(),
                role: WorkflowNodeRole::Step,
            },
            output: "result".to_owned(),
            value_type: WorkflowValueType::Text,
        };
        let skipped = |ids: &[&str]| {
            ids.iter()
                .map(|id| (*id).to_owned())
                .collect::<BTreeSet<_>>()
        };
        for policy in ["required", "advisory"] {
            let workflow = validated(policy);
            let from_c = partition(
                &workflow,
                &["c".to_owned()],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .unwrap();
            assert_eq!(
                referenced_outputs(&workflow, &from_c.reexecuted),
                BTreeSet::from([source("a"), source("b")])
            );
            let refused = if policy == "required" {
                vec![
                    AdmissionViolation::RequiredSkipped {
                        consumer: "c".to_owned(),
                        producer: "a".to_owned(),
                    },
                    AdmissionViolation::RequiredSkipped {
                        consumer: "c".to_owned(),
                        producer: "b".to_owned(),
                    },
                ]
            } else {
                Vec::new()
            };
            let both_skipped = BTreeMap::from([
                ("a".to_owned(), PriorState::Skipped),
                ("b".to_owned(), PriorState::Skipped),
            ]);
            assert_eq!(
                check_inheritance(
                    &workflow,
                    &workflow,
                    &from_c,
                    &both_skipped,
                    &skipped(&["a", "b"])
                ),
                refused,
                "{policy}"
            );
            let a_succeeded = BTreeMap::from([
                ("a".to_owned(), PriorState::Succeeded),
                ("b".to_owned(), PriorState::Skipped),
            ]);
            assert!(
                check_inheritance(
                    &workflow,
                    &workflow,
                    &from_c,
                    &a_succeeded,
                    &skipped(&["b"])
                )
                .is_empty(),
                "{policy}"
            );
            let from_a = partition(
                &workflow,
                &["a".to_owned()],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .unwrap();
            assert_eq!(from_a.reexecuted, ["a", "c"]);
            assert!(
                check_inheritance(
                    &workflow,
                    &workflow,
                    &from_a,
                    &both_skipped,
                    &skipped(&["a", "b"])
                )
                .is_empty(),
                "{policy}"
            );
        }
    }
}
