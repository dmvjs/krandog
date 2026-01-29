// Test btoa and atob functions

// Test basic encoding
const encoded = btoa('hello');
if (encoded !== 'aGVsbG8=') {
    throw new Error(`Expected 'aGVsbG8=', got '${encoded}'`);
}

// Test basic decoding
const decoded = atob('aGVsbG8=');
if (decoded !== 'hello') {
    throw new Error(`Expected 'hello', got '${decoded}'`);
}

// Test round-trip
const original = 'Hello, World!';
const roundtrip = atob(btoa(original));
if (roundtrip !== original) {
    throw new Error(`Round-trip failed: expected '${original}', got '${roundtrip}'`);
}

// Test empty string
const emptyEncoded = btoa('');
if (emptyEncoded !== '') {
    throw new Error(`Empty string should encode to empty string, got '${emptyEncoded}'`);
}

const emptyDecoded = atob('');
if (emptyDecoded !== '') {
    throw new Error(`Empty string should decode to empty string, got '${emptyDecoded}'`);
}

// Test single character
const single = btoa('a');
if (single !== 'YQ==') {
    throw new Error(`Expected 'YQ==', got '${single}'`);
}

const singleDecoded = atob('YQ==');
if (singleDecoded !== 'a') {
    throw new Error(`Expected 'a', got '${singleDecoded}'`);
}

// Test two characters
const two = btoa('ab');
if (two !== 'YWI=') {
    throw new Error(`Expected 'YWI=', got '${two}'`);
}

// Test three characters (no padding)
const three = btoa('abc');
if (three !== 'YWJj') {
    throw new Error(`Expected 'YWJj', got '${three}'`);
}

// Test longer string
const longer = 'The quick brown fox jumps over the lazy dog';
const longerEncoded = btoa(longer);
const longerDecoded = atob(longerEncoded);
if (longerDecoded !== longer) {
    throw new Error(`Longer string round-trip failed`);
}

console.log('atob/btoa tests passed');
