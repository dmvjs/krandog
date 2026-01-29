// Test URL constructor and properties

// Test basic URL
const url1 = new URL('https://example.com:8080/path?foo=bar#hash');

if (url1.protocol !== 'https:') {
    throw new Error(`Expected protocol 'https:', got '${url1.protocol}'`);
}

if (url1.hostname !== 'example.com') {
    throw new Error(`Expected hostname 'example.com', got '${url1.hostname}'`);
}

if (url1.port !== '8080') {
    throw new Error(`Expected port '8080', got '${url1.port}'`);
}

if (url1.pathname !== '/path') {
    throw new Error(`Expected pathname '/path', got '${url1.pathname}'`);
}

if (url1.search !== '?foo=bar') {
    throw new Error(`Expected search '?foo=bar', got '${url1.search}'`);
}

if (url1.hash !== '#hash') {
    throw new Error(`Expected hash '#hash', got '${url1.hash}'`);
}

if (url1.host !== 'example.com:8080') {
    throw new Error(`Expected host 'example.com:8080', got '${url1.host}'`);
}

if (url1.origin !== 'https://example.com:8080') {
    throw new Error(`Expected origin 'https://example.com:8080', got '${url1.origin}'`);
}

if (url1.href !== 'https://example.com:8080/path?foo=bar#hash') {
    throw new Error(`Expected href 'https://example.com:8080/path?foo=bar#hash', got '${url1.href}'`);
}

// Test URL without port
const url2 = new URL('http://example.com/path');
if (url2.hostname !== 'example.com') {
    throw new Error(`Expected hostname 'example.com', got '${url2.hostname}'`);
}
if (url2.port !== '') {
    throw new Error(`Expected empty port, got '${url2.port}'`);
}
if (url2.pathname !== '/path') {
    throw new Error(`Expected pathname '/path', got '${url2.pathname}'`);
}

// Test URL with just domain
const url3 = new URL('https://example.com');
if (url3.pathname !== '/') {
    throw new Error(`Expected pathname '/', got '${url3.pathname}'`);
}

// Test URL with query but no hash
const url4 = new URL('https://example.com/path?query=value');
if (url4.search !== '?query=value') {
    throw new Error(`Expected search '?query=value', got '${url4.search}'`);
}
if (url4.hash !== '') {
    throw new Error(`Expected empty hash, got '${url4.hash}'`);
}

console.log('URL constructor tests passed');
