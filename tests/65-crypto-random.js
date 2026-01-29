// Test: crypto.randomBytes
import crypto from 'crypto';

const bytes16 = crypto.randomBytes(16);
console.log('length:', bytes16.length);
console.log('is buffer:', bytes16.constructor.name);

const bytes32 = crypto.randomBytes(32);
console.log('length 32:', bytes32.length);

const bytes1 = crypto.randomBytes(1);
console.log('single byte valid:', bytes1.length === 1 && bytes1[0] >= 0 && bytes1[0] <= 255);
