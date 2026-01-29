// Test TextDecoder
const decoder = new TextDecoder();

// Test encoding property
if (decoder.encoding !== 'utf-8') {
    throw new Error('TextDecoder encoding should be utf-8');
}

// Test decode() method
const bytes = new Uint8Array([104, 101, 108, 108, 111]);
const result = decoder.decode(bytes);
if (result !== 'hello') {
    throw new Error(`Expected "hello", got "${result}"`);
}

// Test empty array
const empty = decoder.decode(new Uint8Array([]));
if (empty !== '') {
    throw new Error('Empty array should decode to empty string');
}

// Test with regular array
const arr = [72, 105];
const result2 = decoder.decode(arr);
if (result2 !== 'Hi') {
    throw new Error(`Expected "Hi", got "${result2}"`);
}

// Test round-trip with TextEncoder
const encoder = new TextEncoder();
const original = 'Hello, World!';
const encoded = encoder.encode(original);
const decoded = decoder.decode(encoded);
if (decoded !== original) {
    throw new Error(`Round-trip failed: expected "${original}", got "${decoded}"`);
}

console.log('TextDecoder tests passed');
