const GOOGLE_CLIENT_ID = "525900358521-qqueujfcj3cth26ci3humunqskjtcm56.apps.googleusercontent.com"; // (google) client id
const FB_CLIENT_ID = "377291984666448"; // (facebook) client id
const web3 = new Web3(window.ethereum);
var flag = 0;
const SignMessage = "Do not sign this message in any application different than League of Identity. The signature will be used to authenticate to the League of Identity network. Params:"; // CONVENTION: this message should NOT contain any character ':' because this message is concatenated with other info and we use ':' to split the message.

async function checkMetaMaskAvailability() {
    if (window.ethereum) {
        try {
            // Request access to MetaMask accounts
            await window.ethereum.request({
                method: "eth_requestAccounts"
            });
            flag = 1;
            return true;
        } catch (err) {
            document.getElementById("status2").style.color = "red";
            document.getElementById("status2").innerText = "Failed to connect to Metamask";
            console.error("Failed to connect to MetaMask:", err);
            return false;
        }
    } else {
        document.getElementById("status2").style.color = "red";
        document.getElementById("status2").innerText = "Metamask not found";
        console.error("MetaMask not found");
        return false;
    }
}

document.getElementById("instructions").addEventListener("click", async () => {
    document.getElementById("status2").style.color = "white";
    document.getElementById("status3").style.color = "white";
    document.getElementById("status4").style.color = "white";
    document.getElementById("status5").style.color = "white";
    status2.innerText = "";
    status3.innerText = "";
    status4.innerText = "";
    status5.innerText = "";
    status2.innerText = "*Connect*\nClick on \"Get access token\" to log into your Google, Facebook or Ethereum account and get the access token.\nYou can use the access token with the command lines tool of League of Identity.\n\n*Logout*\nClick on \"Logout\" to logout from your account.";

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
    const network = document.getElementById("menu").value;
    if (network === "ethereum") {
        if (flag === 0 && checkMetaMaskAvailability() === false) return;

        const accounts = await web3.eth.getAccounts();
        const myaddr = accounts[0];
        const time = Math.floor(Date.now() / 1000);
        const msg = SignMessage + time + ":" + myaddr;
        const signature = await window.ethereum.request({
            method: 'personal_sign',
            params: [msg, myaddr]
        });
        document.getElementById("status1").style.color = "white";
        document.getElementById("status1").innerText = "Hello, " + myaddr;
        document.getElementById("status2").style.color = "green";
        document.getElementById("status2").innerText = "Your " + network + " access token is: " + time + ":" + myaddr + ":" + signature;

        //var Addr=web3.eth.accounts.recover(msg, signature);
        //console.log(Addr);



        return;
    }


    const options = (network === "google") ? {
        scope: 'email, https://www.googleapis.com/auth/user.phonenumbers.read'
    } : {
        // scope: 'email, user_friends, public_profile, user_likes'
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
