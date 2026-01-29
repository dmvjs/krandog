// Test TextEncoder
const encoder = new TextEncoder();

// Test encoding property
if (encoder.encoding !== 'utf-8') {
    throw new Error('TextEncoder encoding should be utf-8');
}

// Test encode() method
const result = encoder.encode('hello');
if (result.length !== 5) {
    throw new Error(`Expected length 5, got ${result.length}`);
}
if (result[0] !== 104 || result[1] !== 101 || result[2] !== 108 || result[3] !== 108 || result[4] !== 111) {
    throw new Error('Encoded bytes do not match "hello"');
}

// Test empty string
const empty = encoder.encode('');
if (empty.length !== 0) {
    throw new Error('Empty string should encode to empty array');
}

// Test UTF-8 encoding
const emoji = encoder.encode('😀');
if (emoji.length !== 4) {
    throw new Error(`Emoji should encode to 4 bytes, got ${emoji.length}`);
}

console.log('TextEncoder tests passed');
