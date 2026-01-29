// Test: os platform and type
import os from 'os';

const platform = os.platform();
console.log('platform is string:', typeof platform === 'string');
console.log('platform length:', platform.length > 0);

const arch = os.arch();
console.log('arch is string:', typeof arch === 'string');
console.log('arch length:', arch.length > 0);

const type = os.type();
console.log('type is string:', typeof type === 'string');
console.log('type length:', type.length > 0);

console.log('EOL exists:', typeof os.EOL === 'string');
