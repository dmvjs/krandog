// Test: dgram.createSocket
import dgram from 'dgram';

const socket = dgram.createSocket('udp4');
console.log('socket created:', typeof socket === 'object');
console.log('socket has bind:', typeof socket.bind === 'function');
console.log('socket has send:', typeof socket.send === 'function');
console.log('socket has close:', typeof socket.close === 'function');

socket.close();
console.log('socket closed');
