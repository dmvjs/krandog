# krandog

javascript runtime. jsc + es modules only.

## what it does

runs javascript. no commonjs. modern only.

```javascript
import fs from 'fs';
import path from 'path';

const data = fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8');
console.log(data);

fetch('https://api.github.com/users/github')
    .then(r => r.json())
    .then(d => console.log(d.login));
```

## install

```bash
git clone https://github.com/dmvjs/krandog.git
cd krandog
make
```

macos only.

## use

```bash
./krandog script.js
```

## what's in it

- jsc engine (same as bun)
- es modules (import/export)
- event loop (kqueue)
- promises and microtasks
- fetch (libcurl)
- fs module (sync)
- process (argv, env, exit)
- path module
- console (log, error, warn)
- __dirname, __filename

## modules

### fs
```javascript
import fs from 'fs';

fs.readFileSync(path, 'utf8')
fs.writeFileSync(path, data)
fs.existsSync(path)
fs.readdirSync(path)
fs.mkdirSync(path)
```

### path
```javascript
import path from 'path';

path.join('/foo', 'bar')
path.resolve('file.txt')
path.basename('/foo/bar.txt')
path.dirname('/foo/bar')
```

## globals

```javascript
fetch(url)                    // http client
console.log/error/warn        // stdout/stderr
process.argv/env/exit         // process stuff
setTimeout/setInterval        // timers
queueMicrotask                // microtasks
__dirname/__filename          // module paths
```

## test

```bash
make test
```

36 tests pass.

## why

- es modules only. no legacy.
- simple c code. no libuv.
- native macos (kqueue).
- readable. hackable.

## what's missing

http server, async fs, buffers, websockets, child processes, test runner, bundler.

good enough for cli tools and scripts.

## license

mit

---

built with claude sonnet 4.5
