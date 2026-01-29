// Test: clearTimeout
const id = setTimeout(() => console.log('should not print'), 10);
clearTimeout(id);
setTimeout(() => console.log('done'), 20);
