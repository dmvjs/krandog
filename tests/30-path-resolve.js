// Test: path.resolve and isAbsolute
import path from 'path';

console.log(path.resolve('file.txt').includes('/'));
console.log(path.isAbsolute('/foo/bar'));
console.log(path.isAbsolute('foo/bar'));
console.log(path.sep);
