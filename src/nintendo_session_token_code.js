// DISCLAIMER: 
// Do NOT use the `Nintendo` provider in any real world application outside your local computer. The demo in this repository is meant to be just a proof of feasibility about the *possibility* of implementing such mechanism for `Nintendo` *in the future*. Indeed, the current demo uses APIs that are not documented and might be insecure and not used properly. To deploy a `LoI` system with a `Nintendo` provider, `Nintendo` should be contacted and some efficient and secure APIs should be agreed and implemented by `Nintendo` and the `LoI` system should be adapted to them. 

const fs = require('fs');

function nintendo_session_token_code(nst_code) {
    const params = {};
    const codeVerifier = nst_code.split('@')[0];
    const nst_url = nst_code.split('@')[1];
    nst_url.split('#')[1]
        .split('&')
        .forEach(str => {
            const splitStr = str.split('=');
            params[splitStr[0]] = splitStr[1];
        });
    return codeVerifier + "@" + params.session_token_code;
}

module.exports = {
    nintendo_session_token_code
}