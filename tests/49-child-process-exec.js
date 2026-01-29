// Test: child_process.execSync
import { execSync } from 'node:child_process';

const result = execSync('echo "hello from exec"');
console.log(result.trim());
