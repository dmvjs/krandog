// Test: createReadStream
import fs from 'node:fs';

const stream = fs.createReadStream('./tests/data/test.txt');

stream.on('data', (chunk) => {
    console.log(chunk.trim());
});

stream.on('end', () => {
    console.log('done');
});
