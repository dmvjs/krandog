import fs from 'fs';

// Create initial file
fs.writeFileSync('/tmp/append-test.txt', 'Line 1\n');

// Append more lines
fs.appendFileSync('/tmp/append-test.txt', 'Line 2\n');
fs.appendFileSync('/tmp/append-test.txt', 'Line 3\n');

// Read and verify
const content = fs.readFileSync('/tmp/append-test.txt', 'utf8');
console.log('Content:');
console.log(content);

// Cleanup
fs.unlinkSync('/tmp/append-test.txt');
