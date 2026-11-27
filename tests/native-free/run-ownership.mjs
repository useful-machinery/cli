import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as sleep } from 'node:timers/promises';

const SQLITE_BUSY = 5;

function beginExclusive(db) {
  try {
    db.exec('BEGIN EXCLUSIVE');
    return true;
  } catch (error) {
    if (error.errcode !== SQLITE_BUSY) throw error;
    return false;
  }
}

async function holdUntilRelease(release) {
  writeFileSync(`${release}.held`, '');
  const deadline = performance.now() + 30000;
  while (!existsSync(release)) {
    if (performance.now() >= deadline) {
      console.error(`Timed out waiting for ${release}`);
      return 1;
    }
    await sleep(20);
  }
  return 0;
}

async function ownership(command, run, release) {
  const db = new DatabaseSync(join(run, 'owner.db'), { timeout: 0 });
  try {
    if (!beginExclusive(db)) {
      if (command === 'show') {
        console.log('active');
        return 0;
      }
      console.error(`Run ${run} already has an owner`);
      return 1;
    }
    try {
      if (command === 'hold') return await holdUntilRelease(release);
    } finally {
      db.exec('ROLLBACK');
    }
  } finally {
    db.close();
  }
  console.log('free');
  return 0;
}

const [command, run, release, ...extra] = process.argv.slice(2);
if (run && extra.length === 0 && (
  (command === 'show' && release === undefined) || (command === 'hold' && release)
)) {
  process.exitCode = await ownership(command, run, release);
} else {
  console.error('Usage: run-ownership.mjs show RUN | hold RUN RELEASE');
  process.exitCode = 1;
}
