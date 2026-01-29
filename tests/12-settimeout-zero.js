// Test: setTimeout with 0 delay
console.log('sync1');
setTimeout(() => console.log('async'), 0);
console.log('sync2');
