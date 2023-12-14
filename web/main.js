const GOOGLE_CLIENT_ID = "525900358521-qqueujfcj3cth26ci3humunqskjtcm56.apps.googleusercontent.com"; // (google) client id
const FB_CLIENT_ID = "377291984666448"; // (facebook) client id

document.getElementById("instructions").addEventListener("click", async () => {
    document.getElementById("status2").style.color = "white";
    document.getElementById("status3").style.color = "white";
    document.getElementById("status4").style.color = "white";
    document.getElementById("status5").style.color = "white";
    status2.innerText = "";
    status3.innerText = "";
    status4.innerText = "";
    status5.innerText = "";
    status2.innerText = "*Connect*\nClick on \"Get access token\" to log into your Google account and get the access token.\nYou can use the access token with the command lines tool of League of Identity.\n\n*Logout*\nClick on \"Logout\" to logout from your account.";

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

hello.init({
    google: GOOGLE_CLIENT_ID,
    facebook: FB_CLIENT_ID
});
document.getElementById("accountbutton").addEventListener("click", async () => {
    var network = document.getElementById("menu").value;
    const options = (network === "google") ? {
        scope: 'email, https://www.googleapis.com/auth/user.phonenumbers.read'
    } : {
        scope: 'email, user_friends, public_profile'
    };



    hello(network).login(options).then(function() {

        console.log(hello(network).getAuthResponse());

        hello(network).api('/me').then(function(resp) {
            document.getElementById("status1").style.color = "white";
            document.getElementById("status1").innerText = "Hello, " + resp.name + " (" + resp.id + ")";
            document.getElementById("status2").style.color = "green";
            document.getElementById("status2").innerText = "Your " + network + " access token is: " + hello(network).getAuthResponse().access_token;
            console.log(resp);
        });
    });




});
document.getElementById("logout").addEventListener("click", async () => {
    hello('google').logout();
});
