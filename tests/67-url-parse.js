// Test: url.parse
import url from 'url';

const parsed = url.parse('https://example.com:8080/path/to/page?foo=bar&baz=qux#section');
console.log('protocol:', parsed.protocol);
console.log('hostname:', parsed.hostname);
console.log('port:', parsed.port);
console.log('pathname:', parsed.pathname);
console.log('query:', parsed.query);
console.log('hash:', parsed.hash);

const simple = url.parse('http://localhost/test');
console.log('simple protocol:', simple.protocol);
console.log('simple pathname:', simple.pathname);
