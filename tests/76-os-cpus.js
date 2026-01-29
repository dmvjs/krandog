// Test: os.cpus
import os from 'os';

const cpus = os.cpus();
console.log('cpus is array:', Array.isArray(cpus));
console.log('cpus length:', cpus.length > 0);

if (cpus.length > 0) {
    const cpu = cpus[0];
    console.log('cpu has model:', typeof cpu.model === 'string');
    console.log('cpu has speed:', typeof cpu.speed === 'number');
}
