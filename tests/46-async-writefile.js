// Test: Async writeFile
import fs from 'fs';

fs.writeFile('/tmp/krandog-test.txt', 'async content', (err) => {
    if (err) {
        console.log('error');
    } else {
        // Read it back to verify
        const data = fs.readFileSync('/tmp/krandog-test.txt', 'utf8');
        console.log(data);
    }
});
