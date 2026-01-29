// Test: Module caching - same module required twice
const counter1 = require('./modules/counter.js');
console.log(counter1.count);
counter1.increment();
console.log(counter1.count);

const counter2 = require('./modules/counter.js');
console.log(counter2.count); // Should be 2, not 1 (cached)
