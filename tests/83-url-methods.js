// Test URL methods

// Test toString()
const url = new URL('https://example.com:8080/path?foo=bar#hash');
const urlString = url.toString();

if (urlString !== 'https://example.com:8080/path?foo=bar#hash') {
    throw new Error(`Expected 'https://example.com:8080/path?foo=bar#hash', got '${urlString}'`);
}

// Test toJSON()
const urlJson = url.toJSON();
if (urlJson !== 'https://example.com:8080/path?foo=bar#hash') {
    throw new Error(`Expected 'https://example.com:8080/path?foo=bar#hash', got '${urlJson}'`);
}

// Test that toString and toJSON return the same value
if (url.toString() !== url.toJSON()) {
    throw new Error('toString() and toJSON() should return the same value');
}

// Test URL string coercion
const url2 = new URL('http://example.com/test');
const stringified = '' + url2.toString();
if (stringified !== 'http://example.com/test') {
    throw new Error(`String coercion failed: got '${stringified}'`);
}

console.log('URL methods tests passed');
