let order = [];

// nextTick runs before setTimeout
process.nextTick(() => {
    order.push('nextTick 1');
});

setTimeout(() => {
    order.push('setTimeout');
    console.log('Execution order:', order.join(' -> '));
}, 0);

process.nextTick(() => {
    order.push('nextTick 2');
});

order.push('sync');
