import https from 'https';
import fs from 'fs';

console.log('Starting HTTPS server for manual testing...');

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

const server = https.createServer(options, (req) => {
    console.log('Received HTTPS request:', req.method, req.pathname);
    return {
        status: 200,
        body: 'Hello from HTTPS!\n'
    };
});

server.listen(8443, () => {
    console.log('HTTPS server listening on https://localhost:8443');
    console.log('Test with: curl -k https://localhost:8443/');
    console.log('Server will run for 10 seconds...');

    setTimeout(() => {
        console.log('Test timeout - exiting');
        process.exit(0);
    }, 10000);
});
