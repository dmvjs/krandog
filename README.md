# krandog

A modern, opinionated JavaScript runtime built from scratch with JavaScriptCore.

## Features

**krandog is ES modules only. No CommonJS. Modern JavaScript, period.**

- ✅ **JavaScriptCore** - Apple's fast JS engine (same as Bun)
- ✅ **ES Modules** - `import`/`export` only, no `require()`
- ✅ **Event Loop** - Native macOS kqueue, setTimeout, setInterval
- ✅ **Promises** - Full microtask queue, proper async/await
- ✅ **File System** - Sync file operations (`fs` module)
- ✅ **HTTP Client** - `fetch()` with libcurl (HTTPS, redirects)
- ✅ **Process** - argv, env, exit, cwd
- ✅ **Path** - join, resolve, basename, dirname, extname
- ✅ **Console** - log, error, warn, debug (stdout/stderr)
- ✅ **Globals** - `__dirname`, `__filename`

## Installation

```bash
git clone https://github.com/dmvjs/krandog.git
cd krandog
make
```

Requirements: macOS with Xcode Command Line Tools

## Usage

```bash
./krandog script.js
```

## Examples

### Hello World
```javascript
console.log('Hello from krandog!');
```

### Fetch API
```javascript
fetch('https://api.github.com/users/github')
    .then(r => r.json())
    .then(data => console.log(data.login));
```

### File System
```javascript
import fs from 'fs';
import path from 'path';

const data = fs.readFileSync(
    path.join(__dirname, 'config.json'),
    'utf8'
);
console.log(JSON.parse(data));
```

### CLI Tool
```javascript
import fs from 'fs';

const [,, input, output] = process.argv;

if (!input || !output) {
    console.error('Usage: krandog convert <input> <output>');
    process.exit(1);
}

const data = fs.readFileSync(input, 'utf8');
fs.writeFileSync(output, data.toUpperCase());
console.log('✓ Done');
```

### Async Operations
```javascript
setTimeout(() => console.log('later'), 1000);

Promise.resolve('hello')
    .then(msg => console.log(msg));

queueMicrotask(() => console.log('microtask'));
```

## Built-in Modules

### fs
```javascript
import fs from 'fs';

fs.readFileSync(path, encoding)
fs.writeFileSync(path, data)
fs.existsSync(path)
fs.readdirSync(path)
fs.mkdirSync(path)
fs.rmdirSync(path)
fs.unlinkSync(path)
```

### path
```javascript
import path from 'path';

path.join('/foo', 'bar', 'baz.txt')  // '/foo/bar/baz.txt'
path.resolve('file.txt')              // '/current/dir/file.txt'
path.basename('/foo/bar.txt')         // 'bar.txt'
path.dirname('/foo/bar.txt')          // '/foo'
path.extname('file.txt')              // '.txt'
path.isAbsolute('/foo')               // true
path.sep                               // '/'
path.delimiter                         // ':'
```

## Globals

### fetch()
```javascript
const response = await fetch(url);
response.ok        // boolean
response.status    // number
await response.text()
await response.json()
```

### console
```javascript
console.log('info')     // stdout
console.error('error')  // stderr
console.warn('warning') // stderr
console.debug('debug')  // stdout
```

### process
```javascript
process.argv      // ['./krandog', 'script.js', ...args]
process.env       // { HOME: '/Users/...', ... }
process.cwd()     // current directory
process.chdir(dir)
process.exit(code)
process.platform  // 'darwin'
process.version   // 'krandog-0.1.0'
```

### Timers
```javascript
setTimeout(fn, ms)
setInterval(fn, ms)
clearTimeout(id)
clearInterval(id)
```

### Microtasks
```javascript
queueMicrotask(fn)
Promise.resolve().then(fn)
```

### Module globals
```javascript
__dirname   // directory of current file
__filename  // path of current file
```

## Philosophy

**Opinionated and modern:**
- ES modules only (no CommonJS)
- Standards-compliant where it matters
- Simple, readable C codebase
- Native OS integration (kqueue, not libuv)
- Fast iteration, good defaults

**What krandog is:**
- A runtime you can actually understand
- Modern JavaScript without legacy baggage
- Perfect for CLI tools, scripts, automation

**What krandog isn't:**
- Not trying to replace Node.js
- Not trying to be Bun (but inspired by it)
- Not supporting CommonJS ever

## Testing

```bash
make test
```

All 36 tests pass. Test-driven from day one.

## Architecture

- **Runtime**: JavaScriptCore (Apple's JS engine)
- **Event Loop**: Native macOS kqueue
- **HTTP**: libcurl
- **Module System**: Custom ES module transpiler
- **No dependencies** except system libraries

## Comparison

|  | krandog | Node.js | Bun | Deno |
|---|---------|---------|-----|------|
| Engine | JSC | V8 | JSC | V8 |
| Modules | ESM only | Both | Both | ESM |
| Event Loop | kqueue | libuv | custom | Tokio |
| fetch() | ✅ | ❌ | ✅ | ✅ |
| __dirname | ✅ | ✅ | ✅ | ❌ |

## Progress

krandog is ~40-45% of Bun's feature set. All core features work.

**What's implemented:**
- ✅ Runtime, modules, async, timers
- ✅ File system, HTTP client
- ✅ Process, paths, console
- ✅ Promises, microtasks

**What's missing:**
- ❌ HTTP server
- ❌ Async file operations
- ❌ Buffers, streams
- ❌ WebSockets
- ❌ Child processes
- ❌ Test runner, bundler

## License

MIT

## Credits

Built by [@dmvjs](https://github.com/dmvjs) with Claude Sonnet 4.5

---

**krandog: Modern JavaScript, zero legacy.**
