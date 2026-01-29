// Test: crypto.createHash
import crypto from 'crypto';

const hash256 = crypto.createHash('sha256')
    .update('hello world')
    .digest('hex');
console.log('sha256:', hash256.substring(0, 16));

const hashMd5 = crypto.createHash('md5')
    .update('test')
    .digest('hex');
console.log('md5:', hashMd5);

const hashSha1 = crypto.createHash('sha1')
    .update('data')
    .digest('hex');
console.log('sha1:', hashSha1.substring(0, 16));
