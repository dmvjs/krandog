// Test: os directories
import os from 'os';

const homedir = os.homedir();
console.log('homedir is string:', typeof homedir === 'string');
console.log('homedir length:', homedir.length > 0);
console.log('homedir starts with slash:', homedir.startsWith('/'));

const tmpdir = os.tmpdir();
console.log('tmpdir is string:', typeof tmpdir === 'string');
console.log('tmpdir length:', tmpdir.length > 0);

const hostname = os.hostname();
console.log('hostname is string:', typeof hostname === 'string');
console.log('hostname length:', hostname.length > 0);
