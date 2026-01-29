// Test: fs.existsSync
import fs from 'fs';

console.log(fs.existsSync('./tests/fixtures/test.txt'));
console.log(fs.existsSync('./does-not-exist.txt'));
