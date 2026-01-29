// Test: util.inspect
import util from 'util';

const obj1 = { name: 'test', value: 123 };
const inspected1 = util.inspect(obj1);
console.log('object:', inspected1);

const obj2 = { nested: { deep: { value: 'here' } } };
const inspected2 = util.inspect(obj2);
console.log('has nested:', inspected2.includes('nested'));

const arr = [1, 2, 3];
const inspected3 = util.inspect(arr);
console.log('array:', inspected3.includes('1'));
