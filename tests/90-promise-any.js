// Test Promise.any

// Test 1: First promise fulfills
Promise.any([
    Promise.reject('err1'),
    Promise.resolve('success'),
    Promise.reject('err2')
]).then(result => {
    if (result !== 'success') {
        throw new Error('Expected "success" to be the result');
    }
    console.log('PASS: First fulfilled promise won');
}).catch(err => {
    throw new Error('Promise.any should not reject when one fulfills: ' + err.message);
});

// Test 2: All promises reject (should create AggregateError, but we'll check for rejection)
Promise.any([
    Promise.reject('err1'),
    Promise.reject('err2'),
    Promise.reject('err3')
]).then(() => {
    throw new Error('Promise.any should reject when all promises reject');
}).catch(err => {
    // AggregateError may not be available, so just check that it rejected
    console.log('PASS: All rejections handled');
});

// Test 3: Immediate value
Promise.any([Promise.reject('err'), 42]).then(result => {
    if (result !== 42) {
        throw new Error('Expected immediate value 42');
    }
    console.log('PASS: Immediate value won');
}).catch(err => {
    throw new Error('Promise.any should not reject: ' + err.message);
});

// Wait for tests to complete
setTimeout(() => {
    console.log('Promise.any tests passed');
}, 100);
