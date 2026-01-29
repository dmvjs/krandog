// Test: EventEmitter basic
import { EventEmitter } from 'events';

const emitter = new EventEmitter();

emitter.on('test', (msg) => {
    console.log('received:', msg);
});

emitter.on('test', (msg) => {
    console.log('second listener:', msg);
});

console.log('listener count:', emitter.listenerCount('test'));

emitter.emit('test', 'hello');
emitter.emit('test', 'world');
