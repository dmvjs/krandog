// Test: path.join
import path from 'path';

console.log(path.join('/foo', 'bar', 'baz'));
console.log(path.join('/foo', '/bar', 'baz'));
console.log(path.join('foo', 'bar', 'baz'));
console.log(path.join('/foo', '..', 'bar'));
