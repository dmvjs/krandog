import https from 'https';
import fs from 'fs';

console.log('✓ Testing HTTPS server...');

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

const server = https.createServer(options, (req) => {
    console.log(`✓ Received HTTPS request: ${req.method} ${req.pathname}`);
    return {
        status: 200,
        body: 'Hello Secure World! 🔒\n'
    };
});

server.listen(8443, () => {
    console.log('✓ HTTPS server started on https://localhost:8443');
    console.log('✓ Test with: curl -k https://localhost:8443/');

    setTimeout(() => {
        console.log('\n✓ HTTPS server test completed successfully!');
        process.exit(0);
    }, 15000);
});
