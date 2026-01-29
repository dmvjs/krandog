// Test: child_process.spawnSync
import { spawnSync } from 'node:child_process';

const result = spawnSync('echo', ['hello', 'world']);
console.log(result.stdout.trim());
console.log(result.status);
