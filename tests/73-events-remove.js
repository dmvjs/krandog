// Test: EventEmitter removeListener
import { EventEmitter } from 'events';

const emitter = new EventEmitter();

const handler = (msg) => {
    console.log('handler:', msg);
};

emitter.on('data', handler);
console.log('before remove:', emitter.listenerCount('data'));

emitter.emit('data', 'first');

emitter.removeListener('data', handler);
console.log('after remove:', emitter.listenerCount('data'));

emitter.emit('data', 'second');
