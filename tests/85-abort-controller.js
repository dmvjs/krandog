// Test AbortController

// Test constructor
const controller = new AbortController();

if (!controller.signal) {
    throw new Error('AbortController should have a signal property');
}

// Test initial state
if (controller.signal.aborted !== false) {
    throw new Error('Signal should initially not be aborted');
}

// Test abort() method
controller.abort();

if (controller.signal.aborted !== true) {
    throw new Error('Signal should be aborted after abort() is called');
}

// Test abort() with reason
const controller2 = new AbortController();
const reason = new Error('Operation cancelled');
controller2.abort(reason);

if (controller2.signal.aborted !== true) {
    throw new Error('Signal should be aborted');
}

// Test that signal is read-only (can't be reassigned directly in C, but property exists)
const controller3 = new AbortController();
const originalSignal = controller3.signal;

// Verify signal property exists and is the same object
if (controller3.signal !== originalSignal) {
    throw new Error('Signal should remain the same object');
}

console.log('AbortController tests passed');
