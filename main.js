document.getElementById("instructions").addEventListener("click", async () => {
    document.getElementById("status2").style.color = "white";
    document.getElementById("status3").style.color = "white";
    document.getElementById("status4").style.color = "white";
    document.getElementById("status5").style.color = "white";
    status2.innerText = "";
    status3.innerText = "";
    status4.innerText = "";
    status5.innerText = "";
    setTimeout(() => status2.innerText = "*Connect*\nClick on", 100);
    setTimeout(() => status2.innerText = "*Connect*\nClick on \"Get Google access token\" to log", 300);
    setTimeout(() => status2.innerText = "*Connect*\nClick on \"Get Google access token\" to log into your Google account and get the access token.\n", 300);
    setTimeout(() => status2.innerText = "*Connect*\nClick on \"Get Google access token\" to log into your Google account and get the access token.\nYou can use the access token with the command lines tool of League of Identity.\n\n", 300);
    setTimeout(() => status2.innerText = "*Connect*\nClick on \"Get Google access token\" to log into your Google account and get the access token.\nYou can use the access token with the command lines tool of League of Identity.\n\n*Logout*\nClick on \"Logout\" to logout from your Google account.", 300);

});

document.getElementById("minus").addEventListener("click", async () => {

    document.getElementById("status2").innerText = "";
    document.getElementById("status3").innerText = "";
    document.getElementById("status4").innerText = "";
    document.getElementById("status5").innerText = "";
});

hello.on('auth.logout', function() {
    document.getElementById("status1").style.color = "red";
    document.getElementById("status1").innerText = "disconnected";
});

document.getElementById("accountbutton").addEventListener("click", async () => {
    hello.init({
        google: "525900358521-qqueujfcj3cth26ci3humunqskjtcm56.apps.googleusercontent.com" // API key
    });
    hello.on('auth.login', function(auth) {

        console.log(hello('google').getAuthResponse());

        hello(auth.network).api('/me').then(function(resp) {
            document.getElementById("status1").style.color = "white";
            document.getElementById("status1").innerText = "Hello, " + resp.name;
            document.getElementById("status2").style.color = "green";
            document.getElementById("status2").innerText = "Your access token is: " + hello('google').getAuthResponse().access_token;
            console.log(resp);
        });
    });


    hello('google').login({
        //scope: 'email,https://www.googleapis.com/auth/admin.directory.user.readonly,phone,profile,https://www.googleapis.com/auth/user.phonenumbers.read'
        scope: 'email'
    });


});
document.getElementById("logout").addEventListener("click", async () => {
    hello('google').logout();
});
