// Test Promise.prototype.finally

let cleanupCalled = 0;

// Test 1: Finally after resolve
Promise.resolve('success')
    .finally(() => {
        cleanupCalled++;
        console.log('PASS: Finally called after resolve');
    })
    .then(result => {
        if (result !== 'success') {
            throw new Error('Finally should not change the resolved value');
        }
        console.log('PASS: Resolved value preserved');
    });

// Test 2: Finally after reject
Promise.reject(new Error('fail'))
    .finally(() => {
        cleanupCalled++;
        console.log('PASS: Finally called after reject');
    })
    .catch(err => {
        if (err.message !== 'fail') {
            throw new Error('Finally should not change the rejected reason');
        }
        console.log('PASS: Rejected reason preserved');
    });

// Test 3: Finally with returned promise
Promise.resolve('original')
    .finally(() => {
        return new Promise(resolve => {
            setTimeout(() => {
                cleanupCalled++;
                resolve('cleanup done');
            }, 50);
        });
    })
    .then(result => {
        if (result !== 'original') {
            throw new Error('Finally promise should not affect result');
        }
        console.log('PASS: Finally with promise completed');
    });

// Wait for all tests and verify cleanup was called
setTimeout(() => {
    if (cleanupCalled !== 3) {
        throw new Error(`Expected cleanup to be called 3 times, got ${cleanupCalled}`);
    }
    console.log('Promise.finally tests passed');
}, 150);
