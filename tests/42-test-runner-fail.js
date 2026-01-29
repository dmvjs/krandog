// Test: Test runner with failures
test('this passes', () => {
    assert(true);
});

test('this fails', () => {
    assert(false, 'expected failure');
});

test('this also passes', () => {
    assertEqual(1, 1);
});

run();
