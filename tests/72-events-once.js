// Test: EventEmitter once
import { EventEmitter } from 'events';

const emitter = new EventEmitter();

let counter = 0;
emitter.once('temp', () => {
    counter++;
    console.log('once fired:', counter);
});

emitter.emit('temp');
emitter.emit('temp');
emitter.emit('temp');

console.log('final count:', counter);
