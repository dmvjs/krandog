// Test: Promise chaining
Promise.resolve(1)
    .then(x => x + 1)
    .then(x => x * 2)
    .then(x => console.log(x));
console.log('sync');
