// Test: crypto.createHmac
import crypto from 'crypto';

const hmac = crypto.createHmac('sha256', 'secret-key')
    .update('message')
    .digest('hex');
console.log('hmac length:', hmac.length);
console.log('hmac starts with:', hmac.substring(0, 8));

const hmac2 = crypto.createHmac('sha256', 'secret-key')
    .update('message')
    .digest('hex');
console.log('same message same result:', hmac === hmac2);

const hmac3 = crypto.createHmac('sha256', 'different-key')
    .update('message')
    .digest('hex');
console.log('different key different result:', hmac !== hmac3);
