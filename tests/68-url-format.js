// Test: url.format
import url from 'url';

const formatted = url.format({
    protocol: 'https:',
    hostname: 'example.com',
    port: 3000,
    pathname: '/api/users',
    search: '?active=true'
});
console.log('formatted:', formatted);

const simple = url.format({
    protocol: 'http:',
    hostname: 'localhost',
    pathname: '/test'
});
console.log('simple:', simple);
