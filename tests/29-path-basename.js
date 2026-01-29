// Test: path.basename and dirname
import path from 'path';

console.log(path.basename('/foo/bar/baz.txt'));
console.log(path.basename('/foo/bar/baz.txt', '.txt'));
console.log(path.dirname('/foo/bar/baz.txt'));
console.log(path.extname('/foo/bar/baz.txt'));
