// Test: Basic queueMicrotask
console.log('start');
queueMicrotask(() => console.log('microtask'));
console.log('end');
