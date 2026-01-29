// Test: Fetch JSON API
fetch('https://httpbin.org/json').then(response => {
    return response.json();
}).then(data => {
    console.log(data.slideshow.author);
    console.log(typeof data.slideshow.slides.length);
});
