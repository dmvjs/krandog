// Test URLSearchParams

// Test constructor with string
const params1 = new URLSearchParams('?foo=bar&baz=qux');

if (!params1.has('foo')) {
    throw new Error('Should have "foo" parameter');
}

if (!params1.has('baz')) {
    throw new Error('Should have "baz" parameter');
}

if (params1.get('foo') !== 'bar') {
    throw new Error(`Expected foo=bar, got foo=${params1.get('foo')}`);
}

if (params1.get('baz') !== 'qux') {
    throw new Error(`Expected baz=qux, got baz=${params1.get('baz')}`);
}

// Test toString()
const str1 = params1.toString();
if (str1 !== 'foo=bar&baz=qux') {
    throw new Error(`Expected 'foo=bar&baz=qux', got '${str1}'`);
}

// Test empty constructor
const params2 = new URLSearchParams();

if (params2.has('anything')) {
    throw new Error('Empty params should not have any keys');
}

if (params2.toString() !== '') {
    throw new Error('Empty params toString() should be empty string');
}

// Test append()
params2.append('key1', 'value1');
if (!params2.has('key1')) {
    throw new Error('Should have "key1" after append');
}

if (params2.get('key1') !== 'value1') {
    throw new Error(`Expected key1=value1, got key1=${params2.get('key1')}`);
}

params2.append('key2', 'value2');
const str2 = params2.toString();
if (str2 !== 'key1=value1&key2=value2') {
    throw new Error(`Expected 'key1=value1&key2=value2', got '${str2}'`);
}

// Test get() returns null for missing keys
if (params2.get('nonexistent') !== null) {
    throw new Error('get() should return null for missing keys');
}

// Test has() returns false for missing keys
if (params2.has('nonexistent')) {
    throw new Error('has() should return false for missing keys');
}

// Test constructor without leading '?'
const params3 = new URLSearchParams('a=1&b=2');
if (params3.get('a') !== '1' || params3.get('b') !== '2') {
    throw new Error('Should parse query string without leading ?');
}

console.log('URLSearchParams tests passed');
