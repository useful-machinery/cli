import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const helper = fileURLToPath(new URL('./run-ownership.mjs', import.meta.url));

async function poll(predicate) {
  const deadline = performance.now() + 5000;
  while (performance.now() < deadline) {
    if (await predicate()) return performance.now() < deadline;
    await sleep(20);
  }
  return false;
}

function ownershipFixture(t) {
  const run = mkdtempSync(join(tmpdir(), 'useful-run-ownership-'));
  const children = [];
  t.after(async () => {
    for (const { child } of children) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
      }
    }
    await Promise.all(children.map(({ result }) => result));
    rmSync(run, { recursive: true, force: true });
  });

  function start(command, ...args) {
    const { promise: result, resolve } = Promise.withResolvers();
    const child = execFile(
      process.execPath,
      [helper, command, run, ...args],
      { timeout: command === 'hold' ? 15000 : 5000, killSignal: 'SIGKILL' },
      (error, stdout) => resolve({ error, stdout }),
    );
    const invocation = { child, result };
    children.push(invocation);
    return invocation;
  }

  async function show() {
    const { error, stdout } = await start('show').result;
    assert.ifError(error);
    return stdout.trim();
  }

  async function hold() {
    const release = join(run, 'release');
    const holder = start('hold', release);
    const ready = await poll(() => (
      existsSync(`${release}.held`) || holder.child.exitCode !== null
    ));
    assert.ok(ready, 'holder did not signal readiness within 5 s');
    if (!existsSync(`${release}.held`)) assert.ifError((await holder.result).error);
    assert.ok(existsSync(`${release}.held`), 'holder did not create the readiness file');
    assert.equal(await show(), 'active');
    return { ...holder, release };
  }

  return { run, start, show, hold };
}

test('a run is free after its owner releases it', async (t) => {
  const { show, hold } = ownershipFixture(t);
  const { release, result } = await hold();
  writeFileSync(release, '');
  assert.ifError((await result).error);
  assert.equal(await show(), 'free');
});

test('a run is free after its owner is killed', async (t) => {
  const { show, hold } = ownershipFixture(t);
  const { child, result } = await hold();
  assert.ok(child.kill('SIGKILL'));
  const free = await poll(async () => (await show()) === 'free');
  assert.ok(free, 'run still held 5 s after SIGKILL');
  assert.equal((await result).error?.signal, 'SIGKILL');
});

test('a second owner cannot hold an active run', async (t) => {
  const { run, start, hold } = ownershipFixture(t);
  await hold();
  const release = join(run, 'second-release');
  const { error } = await start('hold', release).result;
  assert.ok(
    typeof error?.code === 'number' && error.code !== 0,
    'second hold did not refuse ownership',
  );
  assert.ok(!existsSync(`${release}.held`));
});
