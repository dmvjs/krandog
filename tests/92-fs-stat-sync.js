import fs from 'fs';

// Test statSync on directory
const dirStats = fs.statSync('/tmp');
console.log('Directory stats:');
console.log('  size:', typeof dirStats.size);
console.log('  isDirectory():', dirStats.isDirectory());
console.log('  isFile():', dirStats.isFile());

// Test statSync on file
fs.writeFileSync('/tmp/test-stat.txt', 'test content');
const fileStats = fs.statSync('/tmp/test-stat.txt');
console.log('File stats:');
console.log('  size:', fileStats.size);
console.log('  isDirectory():', fileStats.isDirectory());
console.log('  isFile():', fileStats.isFile());
fs.unlinkSync('/tmp/test-stat.txt');
