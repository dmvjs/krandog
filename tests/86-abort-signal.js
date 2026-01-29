// Test AbortSignal

const controller = new AbortController();
const signal = controller.signal;

// Test initial properties
if (signal.aborted !== false) {
    throw new Error('Signal should initially not be aborted');
}

if (signal.reason !== undefined && signal.reason !== null) {
    throw new Error('Signal reason should initially be undefined or null');
}

if (signal.onabort !== null && signal.onabort !== undefined) {
    throw new Error('Signal onabort should initially be null or undefined');
}

// Test onabort callback
let callbackCalled = false;
signal.onabort = function() {
    callbackCalled = true;
};

controller.abort();

if (!callbackCalled) {
    throw new Error('onabort callback should have been called');
}

if (signal.aborted !== true) {
    throw new Error('Signal should be aborted after abort()');
}

// Test onabort with multiple controllers
const controller2 = new AbortController();
const signal2 = controller2.signal;

let callback2Called = false;
signal2.onabort = function() {
    callback2Called = true;
};

// First signal should still be aborted
if (!signal.aborted) {
    throw new Error('First signal should still be aborted');
}

// Second signal should not be aborted yet
if (signal2.aborted) {
    throw new Error('Second signal should not be aborted yet');
}

if (callback2Called) {
    throw new Error('Second callback should not have been called yet');
}

controller2.abort();

if (!callback2Called) {
    throw new Error('Second callback should have been called');
}

if (!signal2.aborted) {
    throw new Error('Second signal should be aborted');
}

console.log('AbortSignal tests passed');
