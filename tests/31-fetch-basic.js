// Test: Basic fetch
fetch('https://httpbin.org/get').then(response => {
    console.log(response.ok);
    console.log(response.status);
    return response.json();
}).then(data => {
    console.log(typeof data.url);
});
