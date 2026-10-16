const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const ts = require('typescript');

const source = readFileSync(path.join(__dirname, '../../utils/src/extract-product-ids.ts'), 'utf8');
const { outputText } = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020,
    esModuleInterop: true,
  },
});
const fixture = path.join(__dirname, 'product-id-fixture');

function extract(input, writeError) {
  const writes = [];
  vm.runInNewContext(outputText, {
    __dirname: fixture,
    exports: {},
    require(name) {
      if (name === 'path') return path;
      assert.equal(name, 'fs');
      return {
        readFileSync(file, encoding) {
          assert.equal(file, path.join(fixture, 'data/banking-products-output.json'));
          assert.equal(encoding, 'utf8');
          return input;
        },
        writeFileSync(file, content) {
          assert.equal(file, path.join(fixture, 'data/out/banking-product-ids.json'));
          if (writeError) throw writeError;
          writes.push(content);
        },
      };
    },
  });
  return writes;
}

function holder(products) {
  return { holder: { unauthenticated: { banking: { products } } } };
}

test('one product ID is written as valid JSON', () => {
  const writes = extract(JSON.stringify({ holders: [holder([{ productId: 'one' }])] }));
  assert.equal(writes.length, 1);
  assert.deepEqual(JSON.parse(writes[0]), [{ prductId: 'one' }]);
});

test('multiple product IDs preserve order, duplicates, coercion and escaping', () => {
  const ids = [0, false, '', 'quoted"\\\n'];
  const writes = extract(JSON.stringify({ holders: [
    {}, holder(ids.map(productId => ({ productId }))),
    holder([null, {}, { productId: null }, { productId: 'one' }, { productId: 'one' }]),
  ] }));
  assert.equal(writes.length, 1);
  assert.deepEqual(JSON.parse(writes[0]), [...ids, 'one', 'one'].map(id => ({ prductId: String(id) })));
});

test('missing, null and empty collections leave the output unwritten', () => {
  for (const input of [{}, { holders: null }, { holders: [] }, {
    holders: [{}, holder(null), holder([]), holder([null, {}, { productId: null }])],
  }]) {
    assert.deepEqual(extract(JSON.stringify(input)), []);
  }
});

test('malformed JSON and incorrectly typed collections still throw', () => {
  assert.throws(() => extract('{'), error => error.name === 'SyntaxError');
  for (const input of [{ holders: {} }, { holders: [holder({})] }]) {
    assert.throws(() => extract(JSON.stringify(input)), error => error.name === 'TypeError');
  }
});

test('output write failures propagate to the caller', () => {
  const failure = new Error('synthetic write failure');
  assert.throws(
    () => extract(JSON.stringify({ holders: [holder([{ productId: 'one' }])] }), failure),
    error => error === failure,
  );
});
