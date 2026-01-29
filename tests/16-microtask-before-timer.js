// Test: Microtasks run before timers
setTimeout(() => console.log('timer'), 0);
queueMicrotask(() => console.log('microtask'));
console.log('sync');
