// Test: Async readFile
import fs from 'fs';

fs.readFile('./tests/data/test.txt', (err, data) => {
    if (err) {
        console.log('error');
    } else {
        console.log(data);
    }
});
