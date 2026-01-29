// Test: fs.readdirSync
import fs from 'fs';

const files = fs.readdirSync('./tests/fixtures');
console.log(files.length > 0);
console.log(files.includes('test.txt'));
