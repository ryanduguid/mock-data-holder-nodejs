const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const ts = require('typescript');

test('startup keeps environment values out of console output', () => {
  const source = readFileSync(path.join(__dirname, '../src/app.ts'), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
  });
  const output = [];
  const stop = new Error('stop before service configuration');
  const environment = { TEST_VALUE: 'synthetic-private-value-for-regression-test' };
  Object.defineProperty(environment, 'APP_LISTENTING_PORT', {
    get() { throw stop; },
  });
  const context = {
    exports: {},
    process: { env: environment },
    console: { log: (...args) => output.push(args.join(' ')) },
    require(name) {
      if (name === 'express') return () => ({});
      if (name === 'dotenv') return { config() {} };
      return {};
    },
  };

  assert.throws(() => vm.runInNewContext(outputText, context), error => error === stop);
  assert.equal(output.join('\n').includes(environment.TEST_VALUE), false);
});
