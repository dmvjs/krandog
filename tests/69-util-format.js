// Test: util.format
import util from 'util';

const str1 = util.format('Hello %s', 'World');
console.log(str1);

const str2 = util.format('Number: %d, String: %s', 42, 'test');
console.log(str2);

const str3 = util.format('JSON: %j', { name: 'Alice', age: 30 });
console.log(str3);

const str4 = util.format('Multiple %s %s %s', 'a', 'b', 'c');
console.log(str4);
