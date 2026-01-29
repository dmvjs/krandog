// Test Promise.all

// Test 1: All promises resolve
Promise.all([
    Promise.resolve(1),
    Promise.resolve(2),
    Promise.resolve(3)
]).then(results => {
    if (results.length !== 3) {
        throw new Error('Expected 3 results');
    }
    if (results[0] !== 1 || results[1] !== 2 || results[2] !== 3) {
        throw new Error('Results do not match expected values');
    }
    console.log('PASS: All promises resolved');
}).catch(err => {
    throw new Error('Promise.all should not reject: ' + err.message);
});

// Test 2: One promise rejects
Promise.all([
    Promise.resolve(1),
    Promise.reject(new Error('fail')),
    Promise.resolve(3)
]).then(() => {
    throw new Error('Promise.all should reject when one promise fails');
}).catch(err => {
    if (err.message !== 'fail') {
        throw new Error('Expected error message "fail"');
    }
    console.log('PASS: Rejection propagated correctly');
});

// Test 3: Empty array
Promise.all([]).then(results => {
    if (results.length !== 0) {
        throw new Error('Expected empty array');
    }
    console.log('PASS: Empty array resolved');
}).catch(err => {
    throw new Error('Promise.all with empty array should not reject: ' + err.message);
});

// Test 4: Non-promise values
Promise.all([1, 2, 'hello']).then(results => {
    if (results[0] !== 1 || results[1] !== 2 || results[2] !== 'hello') {
        throw new Error('Non-promise values not handled correctly');
    }
    console.log('PASS: Non-promise values handled');
}).catch(err => {
    throw new Error('Promise.all with non-promises should not reject: ' + err.message);
});

// Wait for all tests to complete
setTimeout(() => {
    console.log('Promise.all tests passed');
}, 100);
