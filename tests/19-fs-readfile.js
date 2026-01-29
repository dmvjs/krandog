// Test: fs.readFileSync
import fs from 'fs';

const content = fs.readFileSync('./tests/fixtures/test.txt', 'utf8');
console.log(content);
