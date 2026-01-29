// Test: Default + named exports
import add, { multiply } from './modules/ops.mjs';
console.log(add(2, 3));
console.log(multiply(4, 5));
