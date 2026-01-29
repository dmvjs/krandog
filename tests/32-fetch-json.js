// Test: Fetch JSON API
fetch('https://api.github.com/users/github').then(response => {
    return response.json();
}).then(data => {
    console.log(data.login);
    console.log(typeof data.id);
});
