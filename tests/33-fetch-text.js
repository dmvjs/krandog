// Test: Fetch text
fetch('https://httpbin.org/html').then(response => {
    return response.text();
}).then(text => {
    console.log(text.includes('html'));
    console.log(text.length > 0);
});
