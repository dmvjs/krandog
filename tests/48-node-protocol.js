// Test: node:* protocol
import fs from 'node:fs';
import path from 'node:path';

const testPath = path.join('/tmp', 'test.txt');
console.log(testPath);

fs.writeFileSync(testPath, 'node protocol works');
const data = fs.readFileSync(testPath, 'utf8');
console.log(data);
