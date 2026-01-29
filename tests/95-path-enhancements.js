import path from 'path';

// Test path.parse
const parsed = path.parse('/home/user/file.txt');
console.log('path.parse:');
console.log('  root:', parsed.root);
console.log('  dir:', parsed.dir);
console.log('  base:', parsed.base);
console.log('  name:', parsed.name);
console.log('  ext:', parsed.ext);

// Test path.format
const formatted = path.format({
    dir: '/home/user',
    base: 'file.txt'
});
console.log('path.format:', formatted);

// Test path.normalize
const normalized1 = path.normalize('/foo//bar/../baz');
const normalized2 = path.normalize('/foo/./bar');
console.log('path.normalize:');
console.log('  /foo//bar/../baz ->', normalized1);
console.log('  /foo/./bar ->', normalized2);

// Test path.relative
const relative = path.relative('/foo/bar', '/foo/baz/file.txt');
console.log('path.relative:', relative);
