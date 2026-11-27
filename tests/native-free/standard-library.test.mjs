import assert from 'node:assert/strict';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const tokenPattern = new RegExp([
  String.raw`//[^\r\n]*|/\*[\s\S]*?\*/`,
  String.raw`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\x60(?:\\.|[^\x60\\])*\x60`,
  String.raw`[\w$]+|[^\s]`,
].join('|'), 'g');

function stringValue(token) {
  if (!token || !['"', "'", '`'].includes(token[0])) return undefined;
  const value = token.slice(1, -1);
  if (value.includes('\\') || (token[0] === '`' && value.includes('${'))) return undefined;
  return value;
}

function checkSpecifier(specifier, name) {
  assert.ok(specifier, `${name}: import must have a literal specifier`);
  assert.ok(specifier !== 'node:ffi', `${name}: node:ffi is unavailable to the evidence`);
  if (specifier.startsWith('node:')) return;
  assert.ok(
    specifier.startsWith('./') || specifier.startsWith('../'),
    `${name}: unsupported import ${specifier}`,
  );
  const target = resolve(directory, specifier);
  assert.ok(
    dirname(target) === directory && lstatSync(target, { throwIfNoEntry: false })?.isFile(),
    `${name}: import must refer to a file in ${directory}: ${specifier}`,
  );
}

function checkSource(source, name) {
  // Keep comments and strings whole so sample code and messages do not count as imports.
  const tokens = source.match(tokenPattern) ?? [];
  const code = tokens.filter((token) => !token.startsWith('//') && !token.startsWith('/*'));
  for (const [index, token] of code.entries()) {
    const next = code[index + 1];
    assert.ok(
      token !== 'require' || next !== '(',
      `${name}: require is unavailable to the evidence`,
    );
    assert.notEqual(token, 'createRequire', `${name}: createRequire is unavailable to the evidence`);
    assert.ok(
      token !== 'process' || next !== '.' || code[index + 2] !== 'dlopen',
      `${name}: process.dlopen is unavailable to the evidence`,
    );
    if (token !== 'import' || next === '.') continue;
    if (next === '(') {
      const end = code[index + 3];
      assert.ok(end === ')' || end === ',', `${name}: import must have a literal specifier`);
      checkSpecifier(stringValue(code[index + 2]), name);
    } else {
      const from = code.findIndex((part, position) => (
        position > index && part === 'from' && stringValue(code[position + 1]) !== undefined
      ));
      const specifier = stringValue(next)
        ?? (from === -1 ? undefined : stringValue(code[from + 1]));
      checkSpecifier(specifier, name);
    }
  }
}

test('native-free evidence uses Node built-ins and local files', () => {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.mjs')) {
      checkSource(readFileSync(resolve(directory, entry.name), 'utf8'), entry.name);
    }
  }
});

test('the source check refuses external imports and native loading', () => {
  for (const source of [
    "import x from 'left-pad'",
    "import /* dynamic */ ('left-pad')",
    "import 'node:ffi'",
    "import '../fixtures/command-scenarios.json'",
    "require('node:fs')",
    "import { createRequire } from 'node:module'",
    "process.dlopen(module, './binding.node')",
  ]) {
    assert.throws(() => checkSource(source, 'fixture'), { code: 'ERR_ASSERTION' }, source);
  }
});
