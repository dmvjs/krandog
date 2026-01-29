// Test: fs.writeFileSync
import fs from 'fs';

fs.writeFileSync('/tmp/krandog-test.txt', 'test data');
const content = fs.readFileSync('/tmp/krandog-test.txt', 'utf8');
console.log(content);
fs.unlinkSync('/tmp/krandog-test.txt');
