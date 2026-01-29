// Test: net module exports
import net from 'net';

console.log('createServer exists:', typeof net.createServer === 'function');
console.log('createConnection exists:', typeof net.createConnection === 'function');
console.log('connect exists:', typeof net.connect === 'function');

const server = net.createServer();
console.log('server created:', typeof server === 'object');
console.log('server has listen:', typeof server.listen === 'function');
