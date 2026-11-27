import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createWriteStream, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { signalGroup, waitForGroupExit } from './step-guard.mjs';

const [directory, grace, separator, ...argv] = process.argv.slice(2);
const graceMs = Number(grace);
if (!directory || !grace || !Number.isFinite(graceMs) || graceMs < 0 || separator !== '--' || !argv.length) {
  throw new Error('Usage: step-owner.mjs RECORD_DIR GRACE_MS -- ARGV...');
}

const { promise: stopRequested, resolve: requestStop } = Promise.withResolvers();
process.on('SIGTERM', requestStop);
process.stdout.write('owner stdout\n');

const guardProgram = fileURLToPath(new URL('./step-guard.mjs', import.meta.url));
const guard = spawn(process.execPath, [guardProgram, ...argv], {
  detached: true,
  // Keep the guard on the owner's stdout, including when stdout is a terminal.
  stdio: ['pipe', 'inherit', 'pipe', 'pipe'],
});
const guardExited = once(guard, 'exit');
const outputCopied = pipeline(guard.stderr, createWriteStream(join(directory, 'output')));

function recordPid(name, pid) {
  const path = join(directory, name);
  writeFileSync(`${path}.tmp`, `${pid}\n`);
  renameSync(`${path}.tmp`, path);
}

if (guard.pid === undefined) await guardExited;
recordPid('guard', guard.pid);
const report = guard.stdio[3].setEncoding('utf8');
let reported = '';
for await (const chunk of report) reported += chunk;
const group = Number(reported.trim());
if (!Number.isSafeInteger(group) || group <= 1) throw new Error('Guard did not report a step group');
recordPid('group', group);

const stopped = await Promise.race([
  stopRequested.then(() => true),
  guardExited.then(() => false),
]);
let gone = false;
if (stopped) {
  signalGroup(group, 'SIGINT');
  gone = await waitForGroupExit(group, graceMs);
}
if (!gone) {
  signalGroup(group, 'SIGKILL');
  await waitForGroupExit(group);
}

await Promise.all([guardExited, outputCopied]);
process.off('SIGTERM', requestStop);
