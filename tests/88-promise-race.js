// Test Promise.race

// Test 1: First promise resolves
Promise.race([
    Promise.resolve('fast'),
    new Promise(resolve => setTimeout(() => resolve('slow'), 100))
]).then(result => {
    if (result !== 'fast') {
        throw new Error('Expected "fast" to win the race');
    }
    console.log('PASS: Fastest promise won');
}).catch(err => {
    throw new Error('Promise.race should not reject: ' + err.message);
});

// Test 2: First promise rejects
Promise.race([
    Promise.reject(new Error('fast fail')),
    new Promise(resolve => setTimeout(() => resolve('slow'), 100))
]).then(() => {
    throw new Error('Promise.race should reject with first rejection');
}).catch(err => {
    if (err.message !== 'fast fail') {
        throw new Error('Expected error message "fast fail"');
    }
    console.log('PASS: First rejection propagated');
});

// Test 3: Immediate value
Promise.race([42, Promise.resolve(100)]).then(result => {
    if (result !== 42) {
        throw new Error('Expected immediate value to win');
    }
    console.log('PASS: Immediate value won');
}).catch(err => {
    throw new Error('Promise.race should not reject: ' + err.message);
});

// Wait for tests to complete
setTimeout(() => {
    console.log('Promise.race tests passed');
}, 150);
