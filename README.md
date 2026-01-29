# krandog

javascript runtime. jsc + es modules only.

## what it does

runs javascript. no commonjs. modern only.

```javascript
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import chalk from 'chalk';  // from node_modules

const data = fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8');
console.log(chalk.green(data));

const output = execSync('git status');
console.log(output);

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
- npm package resolution
- node:* protocol
- child_process (spawn, exec)
- event loop (kqueue)
- promises and microtasks
- fetch (libcurl)
- http server
- websockets (client + server)
- net (tcp sockets)
- crypto (hash, hmac, random)
- url (parse, format)
- util (format, inspect)
- events (EventEmitter)
- os (platform, arch, cpus, etc)
- test runner
- buffer (binary data)
- fs module (sync + async + streams)
- process (argv, env, exit)
- path module
- console (log, error, warn)
- __dirname, __filename

## npm packages

works with node_modules. explicit names only.

```javascript
import chalk from 'chalk';
import express from 'express';
import { readFile } from 'fs-extra';
```

resolution:
- walks up directory tree looking for node_modules
- reads package.json for entry point (module, then main)
- no fuzzy matching or magic

## modules

### fs
```javascript
import fs from 'fs';

// sync
fs.readFileSync(path, 'utf8')
fs.writeFileSync(path, data)
fs.existsSync(path)
fs.readdirSync(path)
fs.mkdirSync(path)

// async
fs.readFile(path, (err, data) => {})
fs.writeFile(path, data, (err) => {})

// streams
const readStream = fs.createReadStream(path)
const writeStream = fs.createWriteStream(path)
```

### path
```javascript
import path from 'path';

path.join('/foo', 'bar')
path.resolve('file.txt')
path.basename('/foo/bar.txt')
path.dirname('/foo/bar')
```

### http server
```javascript
serve(3000, (req) => {
    console.log(req.method, req.url);
    return { status: 200, body: 'hello' };
});
```

### websockets
```javascript
// client
const ws = new WebSocket('ws://localhost:8080');
ws.onopen = () => ws.send('hello');
ws.onmessage = (event) => console.log(event.data);
ws.onclose = () => console.log('closed');

// server
serve(8080, (req) => {
    if (req.type === 'websocket') {
        console.log('received:', req.data);
        req.ws.send('echo: ' + req.data);
        return;
    }
    return { status: 200, body: 'http' };
});
```

### crypto
```javascript
import crypto from 'crypto';

// random bytes
const buf = crypto.randomBytes(32);

// hash
const hash = crypto.createHash('sha256')
    .update('data')
    .digest('hex');

// hmac
const hmac = crypto.createHmac('sha256', 'secret')
    .update('message')
    .digest('hex');

// algorithms: md5, sha1, sha256, sha512
```

### net (tcp)
```javascript
import net from 'net';

// tcp server
const server = net.createServer((socket) => {
    socket.ondata = (data) => {
        console.log('received:', data);
        socket.write('echo: ' + data);
    };
    socket.onend = () => console.log('client disconnected');
});
server.listen(8080);

// tcp client
const client = net.createConnection(8080, 'localhost');
client.onconnect = () => client.write('hello');
client.ondata = (data) => console.log('got:', data);
client.onend = () => console.log('done');
```

### url
```javascript
import url from 'url';

// parse url
const parsed = url.parse('https://example.com:8080/path?foo=bar#hash');
console.log(parsed.protocol);  // https:
console.log(parsed.hostname);  // example.com
console.log(parsed.port);      // 8080
console.log(parsed.pathname);  // /path
console.log(parsed.query);     // foo=bar

// format url
const formatted = url.format({
    protocol: 'https:',
    hostname: 'example.com',
    pathname: '/api',
    search: '?key=value'
});
```

### util
```javascript
import util from 'util';

// format strings
const msg = util.format('Hello %s, age %d', 'Alice', 25);

// inspect objects
console.log(util.inspect({ name: 'test', value: 123 }));
```

### events (EventEmitter)
```javascript
import { EventEmitter } from 'events';

// create emitter
const emitter = new EventEmitter();

// listen to events
emitter.on('data', (msg) => console.log('got:', msg));
emitter.once('temp', () => console.log('one time'));

// emit events
emitter.emit('data', 'hello');
emitter.emit('temp');

// remove listeners
emitter.removeListener('data', handler);
emitter.removeAllListeners('data');

// introspection
emitter.listenerCount('data');
emitter.listeners('data');
emitter.eventNames();

// extend EventEmitter
class MyEmitter extends EventEmitter {
    doWork() {
        this.emit('done', { status: 'ok' });
    }
}
```

### os
```javascript
import os from 'os';

os.platform()    // 'darwin', 'linux', 'win32'
os.arch()        // 'x64', 'arm64', 'ia32', 'arm'
os.homedir()     // '/Users/username'
os.tmpdir()      // '/tmp'
os.hostname()    // 'macbook-pro'
os.type()        // 'Darwin', 'Linux', 'Windows_NT'
os.cpus()        // [{ model: 'Apple M1', speed: 0 }, ...]
os.EOL           // '\n' on unix
```

### test runner
```javascript
test('addition works', () => {
    assertEqual(1 + 1, 2);
});

test('truth is truthy', () => {
    assert(true);
});

run();
```

### buffer
```javascript
const buf = Buffer.from('hello');
console.log(buf.length);  // 5
console.log(buf[0]);      // 104 ('h')

const buf2 = Buffer.alloc(10);
console.log(buf2.length); // 10
```

### async operations
```javascript
import fs from 'fs';

fs.readFile('data.txt', (err, data) => {
    if (err) throw err;
    console.log(data);
});

fs.writeFile('out.txt', 'content', (err) => {
    if (err) throw err;
    console.log('written');
});
```

### child_process
```javascript
import { execSync, spawnSync } from 'node:child_process';

// simple command execution
const output = execSync('ls -la');
console.log(output);

// spawn with arguments
const result = spawnSync('git', ['status']);
console.log(result.stdout);
console.log(result.status);
```

### streams
```javascript
import fs from 'node:fs';

// read stream
const readStream = fs.createReadStream('large-file.txt');
readStream.on('data', (chunk) => {
    console.log(chunk);
});
readStream.on('end', () => {
    console.log('done');
});

// write stream
const writeStream = fs.createWriteStream('output.txt');
writeStream.write('hello\n');
writeStream.write('world\n');
writeStream.end();
```

## globals

```javascript
fetch(url)                    // http client
serve(port, handler)          // http server
WebSocket(url)                // websocket client
test(name, fn)                // register test
assert(condition, message)    // test assertion
assertEqual(a, b)             // equality assertion
run()                         // run tests
Buffer.from(string)           // create buffer
Buffer.alloc(size)            // allocate buffer
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

52 tests pass.

## why

- es modules only. no legacy.
- simple c code. no libuv.
- native macos (kqueue).
- readable. hackable.

## what's missing

typescript, bundler, more node apis (dns, tls/https, zlib, stream base classes).

good enough for cli tools, scripts, networking, real-time apps, and most npm packages.

## license

mit
