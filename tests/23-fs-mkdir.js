// Test: fs.mkdirSync and rmdirSync
import fs from 'fs';

const dir = '/tmp/krandog-test-dir';
fs.mkdirSync(dir);
console.log(fs.existsSync(dir));

fs.writeFileSync(dir + '/file.txt', 'data');
console.log(fs.existsSync(dir + '/file.txt'));

fs.unlinkSync(dir + '/file.txt');
fs.rmdirSync(dir);
console.log(fs.existsSync(dir));
