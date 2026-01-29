// Test Promise.allSettled

// Test 1: Mix of resolved and rejected promises
Promise.allSettled([
    Promise.resolve(1),
    Promise.reject(new Error('error')),
    Promise.resolve(3)
]).then(results => {
    if (results.length !== 3) {
        throw new Error('Expected 3 results');
    }

    // Check first result (fulfilled)
    if (results[0].status !== 'fulfilled' || results[0].value !== 1) {
        throw new Error('First result should be fulfilled with value 1');
    }

    // Check second result (rejected)
    if (results[1].status !== 'rejected' || results[1].reason.message !== 'error') {
        throw new Error('Second result should be rejected with error');
    }

    // Check third result (fulfilled)
    if (results[2].status !== 'fulfilled' || results[2].value !== 3) {
        throw new Error('Third result should be fulfilled with value 3');
    }

    console.log('PASS: All promises settled correctly');
}).catch(err => {
    throw new Error('Promise.allSettled should not reject: ' + err.message);
});

// Test 2: All promises reject
Promise.allSettled([
    Promise.reject('err1'),
    Promise.reject('err2')
]).then(results => {
    if (results.length !== 2) {
        throw new Error('Expected 2 results');
    }

    if (results[0].status !== 'rejected' || results[0].reason !== 'err1') {
        throw new Error('First result should be rejected');
    }

    if (results[1].status !== 'rejected' || results[1].reason !== 'err2') {
        throw new Error('Second result should be rejected');
    }

    console.log('PASS: All rejections handled');
}).catch(err => {
    throw new Error('Promise.allSettled should not reject: ' + err.message);
});

// Test 3: Empty array
Promise.allSettled([]).then(results => {
    if (results.length !== 0) {
        throw new Error('Expected empty array');
    }
    console.log('PASS: Empty array handled');
}).catch(err => {
    throw new Error('Promise.allSettled should not reject: ' + err.message);
});

// Wait for tests to complete
setTimeout(() => {
    console.log('Promise.allSettled tests passed');
}, 100);
