// Test: Buffer.from
const buf = Buffer.from('hello');
console.log(buf.length);
console.log(buf[0]); // 'h' = 104
console.log(buf[4]); // 'o' = 111
