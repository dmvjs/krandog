// Test: __dirname in imported module
import { moduleDirname } from './modules/dirname-test.mjs';
console.log(moduleDirname.includes('modules'));
console.log(moduleDirname.includes('tests'));
