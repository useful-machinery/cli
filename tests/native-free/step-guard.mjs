import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { closeSync, writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

export function signalGroup(group, signal) {
  try {
    return process.kill(-group, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
    return false;
  }
}

export async function waitForGroupExit(group, timeout = Infinity) {
  const deadline = performance.now() + timeout;
  while (signalGroup(group, 0)) {
    if (performance.now() >= deadline) return false;
    await sleep(20);
  }
  return true;
}

async function guardStep([program, ...args]) {
  const control = process.stdin;
  const ownerGone = once(control, 'end');
  control.resume();
  // Open the Node streams before spawning to exercise libuv's handling of inherited flags.
  process.stdout.write('');
  process.stderr.write('');

  const step = spawn(program, args, {
    detached: true,
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  const leaderExited = once(step, 'exit');
  if (step.pid === undefined) await leaderExited;
  try {
    writeFileSync(3, `${step.pid}\n`);
    closeSync(3);
    await Promise.race([ownerGone, leaderExited]);
  } finally {
    signalGroup(step.pid, 'SIGKILL');
    await waitForGroupExit(step.pid);
    control.destroy();
  }
}

if (import.meta.main) await guardStep(process.argv.slice(2));
