import https from 'https';
import fs from 'fs';

console.log('Testing HTTPS server creation...');

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

try {
    const server = https.createServer(options, (req) => {
        console.log('Received HTTPS request:', req.method, req.pathname);
        return {
            status: 200,
            headers: { 'Content-Type': 'text/plain' },
            body: 'Hello HTTPS!'
        };
    });

    server.listen(8443, () => {
        console.log('HTTPS server started successfully');
        // For now, just verify the server starts
        setTimeout(() => {
            console.log('Test passed - HTTPS server created');
            process.exit(0);
        }, 100);
    });
} catch (err) {
    console.error('Failed to create HTTPS server:', err);
    process.exit(1);
}
