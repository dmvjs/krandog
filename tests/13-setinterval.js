// Test: setInterval
let count = 0;
const id = setInterval(() => {
    count++;
    console.log(count);
    if (count === 3) {
        clearInterval(id);
    }
}, 10);
