// Test: dns.lookup
import dns from 'dns';

dns.lookup('localhost', (err, address) => {
    if (err) {
        console.log('error:', err);
        return;
    }
    console.log('address type:', typeof address);
    console.log('is loopback:', address === '127.0.0.1' || address === '::1');
});
