import https from 'https';
import fs from 'fs';

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

let requestCount = 0;

const server = https.createServer(options, (req) => {
    requestCount++;
    console.log(`[${requestCount}] ${req.method} ${req.pathname}`);

    return {
        status: 200,
        body: `HTTPS Response #${requestCount}: ${req.pathname} 🔒\n`
    };
});

server.listen(8443, () => {
    console.log('HTTPS Server Ready: https://localhost:8443\n');

    setTimeout(() => {
        console.log(`\nTest complete! Handled ${requestCount} encrypted request(s).`);
        process.exit(0);
    }, 10000);
});
