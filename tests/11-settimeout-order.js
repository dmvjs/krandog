// Test: setTimeout execution order
setTimeout(() => console.log('third'), 30);
setTimeout(() => console.log('first'), 10);
setTimeout(() => console.log('second'), 20);
