import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { constants, tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const ownerProgram = fileURLToPath(new URL('./step-owner.mjs', import.meta.url));
const ownerIdentity = `
import json, os, sys
path = os.path.join(sys.argv[1], 'owner.json')
with open(path + '.tmp', 'w') as record:
    json.dump(dict(pid=os.getpid(), session=os.getsid(0), group=os.getpgrp(),
                   terminal=os.isatty(1)), record)
os.rename(path + '.tmp', path)
os.execv(sys.argv[2], sys.argv[2:])
`;
const pseudoTerminal = `
import os, pty, sys
sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))
`;
const recordStep = `
import json, os, signal, subprocess, sys, time
directory, mode = sys.argv[1:]

def record(name, value):
    path = os.path.join(directory, name)
    with open(path + '.tmp', 'w') as file:
        json.dump(value, file)
    os.rename(path + '.tmp', path)

def interrupt(number, frame):
    record('interrupted.json', number)
    sys.exit(0)

signal.signal(signal.SIGINT, signal.SIG_IGN if mode == 'ignore' else interrupt)
try:
    os.close(os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY))
    tty_errno = None
except OSError as error:
    tty_errno = error.errno
record('step.json', dict(pid=os.getpid(), session=os.getsid(0), group=os.getpgrp(),
                         tty_errno=tty_errno, blocking=[os.get_blocking(fd) for fd in range(3)],
                         stdin_eof=os.read(0, 1) == b''))
background = subprocess.Popen(['sleep', '300'])
print('step stdout', flush=True)
print('step stderr', file=sys.stderr, flush=True)
record('background.json', dict(pid=background.pid, group=os.getpgid(background.pid)))
if mode == 'leave-background':
    while not os.path.exists(os.path.join(directory, 'release')):
        time.sleep(0.02)
else:
    background.wait()
`;

async function poll(predicate) {
  const deadline = performance.now() + 10000;
  while (performance.now() < deadline) {
    if (predicate()) return performance.now() < deadline;
    await sleep(20);
  }
  return false;
}

function signalIfPresent(pid, signal) {
  if (pid === undefined) return false;
  try {
    return process.kill(pid, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
    return false;
  }
}

async function startStep(t, { terminal = false, mode = 'interrupt', grace = 400 } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'useful-step-group-'));
  const ownerArgs = [
    '-c', ownerIdentity, directory, process.execPath, ownerProgram, directory, String(grace), '--',
    'python3', '-c', recordStep, directory, mode,
  ];
  const { promise: result, resolve } = Promise.withResolvers();
  const launcher = execFile(
    'python3',
    terminal ? ['-c', pseudoTerminal, 'python3', ...ownerArgs] : ownerArgs,
    { timeout: 16000, killSignal: 'SIGKILL' },
    (error, stdout, stderr) => resolve({ error, stdout, stderr }),
  );

  function read(name) {
    try {
      return readFileSync(join(directory, name), 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      return undefined;
    }
  }

  function readRecord(name) {
    const contents = read(name);
    return contents ? JSON.parse(contents) : undefined;
  }

  let groupGone = false;
  let guardGone = false;
  t.after(async () => {
    if (launcher.exitCode === null && launcher.signalCode === null) {
      signalIfPresent(readRecord('owner.json')?.pid, 'SIGKILL');
      launcher.kill('SIGKILL');
    }
    if (!guardGone) signalIfPresent(readRecord('guard'), 'SIGKILL');
    if (!groupGone) {
      const leader = readRecord('step.json')?.pid;
      const group = readRecord('group') ?? leader;
      if (group !== undefined) signalIfPresent(-group, 'SIGKILL');
      signalIfPresent(leader, 'SIGKILL');
      signalIfPresent(readRecord('background.json')?.pid, 'SIGKILL');
    }
    await result;
    rmSync(directory, { recursive: true, force: true });
  });

  const ready = await poll(() => (
    (readRecord('group') && readRecord('background.json')) ||
    launcher.exitCode !== null || launcher.signalCode !== null
  ));
  assert.ok(ready, 'step did not signal readiness within 10 s');
  if (launcher.exitCode !== null || launcher.signalCode !== null) {
    const { stderr, stdout } = await result;
    assert.fail(`owner exited before the step was ready\n${stderr || stdout}`);
  }

  const owner = readRecord('owner.json');
  const guard = readRecord('guard');
  const group = readRecord('group');
  const step = readRecord('step.json');
  const background = readRecord('background.json');
  assert.equal(owner.terminal, terminal);
  assert.equal(step.group, group);
  assert.equal(step.group, step.pid);
  assert.equal(step.session, step.pid);
  assert.notEqual(step.group, owner.group);
  assert.notEqual(step.session, owner.session);
  assert.equal(step.tty_errno, constants.errno.ENXIO);
  assert.deepEqual(step.blocking, [true, true, true]);
  assert.equal(step.stdin_eof, true);
  assert.equal(background.group, group);
  assert.ok(process.kill(owner.pid, 0));
  assert.ok(process.kill(-group, 0));
  assert.ok(process.kill(background.pid, 0));

  async function expectGroupGone() {
    groupGone = await poll(() => !signalIfPresent(-group, 0));
    assert.ok(groupGone, `process group ${group} still present after 10 s`);
  }

  async function expectOwnerExit() {
    const { error, stdout } = await result;
    assert.ifError(error);
    assert.match(stdout, /owner stdout/);
    assert.match(stdout, /step stdout/);
    assert.match(read('output'), /step stderr/);
  }

  async function expectGuardExit() {
    guardGone = await poll(() => !signalIfPresent(guard, 0));
    assert.ok(guardGone, `guard ${guard} still present after 10 s`);
  }

  return {
    directory, grace, owner, guard, readRecord, result, expectGroupGone, expectOwnerExit,
    expectGuardExit,
  };
}

for (const terminal of [false, true]) {
  test(`a step with ${terminal ? 'terminal' : 'piped'} output ends on SIGINT`, async (t) => {
    const step = await startStep(t, { terminal });
    process.kill(step.owner.pid, 'SIGTERM');
    await step.expectGroupGone();
    await step.expectOwnerExit();
    assert.equal(step.readRecord('interrupted.json'), constants.signals.SIGINT);
  });
}

test('a step ignoring SIGINT is killed after the grace period', async (t) => {
  const step = await startStep(t, { mode: 'ignore' });
  const requested = performance.now();
  process.kill(step.owner.pid, 'SIGTERM');
  await step.expectGroupGone();
  assert.ok(performance.now() - requested >= step.grace);
  await step.expectOwnerExit();
});

test('the guard removes the step group when the owner is killed', async (t) => {
  const step = await startStep(t);
  process.kill(step.owner.pid, 'SIGKILL');
  await step.expectGroupGone();
  await step.expectGuardExit();
  assert.equal((await step.result).error?.signal, 'SIGKILL');
});

test('the owner removes the step group when the guard is killed', async (t) => {
  const step = await startStep(t);
  process.kill(step.guard, 'SIGKILL');
  await step.expectGroupGone();
  await step.expectOwnerExit();
});

test('the guard removes background processes after the leader exits', async (t) => {
  const step = await startStep(t, { mode: 'leave-background' });
  writeFileSync(join(step.directory, 'release'), '');
  await step.expectGroupGone();
  await step.expectOwnerExit();
});
