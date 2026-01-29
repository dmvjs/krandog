// Test: createWriteStream
import fs from 'node:fs';

const stream = fs.createWriteStream('/tmp/stream-test.txt');

stream.write('line 1\n');
stream.write('line 2\n');
stream.end();

// Wait a bit then read back
setTimeout(() => {
    const data = fs.readFileSync('/tmp/stream-test.txt', 'utf8');
    console.log(data);
}, 100);
