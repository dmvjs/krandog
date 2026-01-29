import fs from 'fs';

// Create a test file
fs.writeFileSync('/tmp/rename-source.txt', 'rename test');

// Rename it
fs.renameSync('/tmp/rename-source.txt', '/tmp/rename-dest.txt');

// Verify old name doesn't exist and new name does
console.log('Source exists:', fs.existsSync('/tmp/rename-source.txt'));
console.log('Destination exists:', fs.existsSync('/tmp/rename-dest.txt'));
console.log('Content:', fs.readFileSync('/tmp/rename-dest.txt', 'utf8'));

// Cleanup
fs.unlinkSync('/tmp/rename-dest.txt');
