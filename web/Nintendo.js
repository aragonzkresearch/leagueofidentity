// DISCLAIMER: 
// Do NOT use the `Nintendo` provider in any real world application outside your local computer. The demo in this repository is meant to be just a proof of feasibility about the *possibility* of implementing such mechanism for `Nintendo` *in the future*. Indeed, the current demo uses APIs that are not documented and might be insecure and not used properly. To deploy a `LoI` system with a `Nintendo` provider, `Nintendo` should be contacted and some efficient and secure APIs should be agreed and implemented by `Nintendo` and the `LoI` system should be adapted to them. 
// See comments in the file ../src/nintendo_provider/loi_server_nintendo.js
// We discourage any use outside your local computer!!!

const CLIENT_ID = '71b963c1b7b6d119';

function generateRandom(length) {
    return btoa(String.fromCodePoint(...crypto.getRandomValues(new Uint8Array(length)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=*$/g, '');
}

function calculateChallenge(codeVerifier) {
    return crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(codeVerifier));
}

async function bytesToBase64DataUrl(bytes, type = "application/octet-stream") {
    return await new Promise((resolve, reject) => {
        const reader = Object.assign(new FileReader(), {
            onload: () => resolve(reader.result),
            onerror: () => reject(reader.error),
        });
        reader.readAsDataURL(new File([bytes], "", {
            type
        }));
    });
}


function generateAuthenticationParams() {
    var state = generateRandom(36);
    var codeVerifier = generateRandom(32);
    //    state="aXKcCepajRYidshmMOyuK4Fh_N2jzDsw1QM-cwK5fCW_YZ7G"; // use it for debug
    //codeVerifier="S_osxJeP2y9G6ySkkrUoancYztkdrPzi_edBY12Dt9U"; // use it for debug
    // codeVerifier = "P_osxJeP2y9G6ySkkrUoancYztkdrPzi_edBY12Dt9U"; // use it for debug
    const codeChallenge = crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(codeVerifier)).then(function(digest) {
        return bytesToBase64DataUrl(digest);
    });
    return {
        state,
        codeChallenge,
        codeVerifier
    };
}

function Nintendo() {

    let authParams = {};
    authParams = generateAuthenticationParams();
    return authParams.codeChallenge.then(function(codeChallenge) {
        codeChallenge = codeChallenge.split(',')[1].replace(/\+/g, '-').replace(/\//g, '_').replace(/=*$/g, '');
        const params = {
            state: authParams.state,
            redirect_uri: 'npf' + CLIENT_ID + '://auth&client_id=' + CLIENT_ID,
            //scope: 'openid%20user%20user.birthday%20user.mii%20user.screenName',
            scope: 'openid',
            response_type: 'session_token_code',
            session_token_code_challenge: codeChallenge,
            session_token_code_challenge_method: 'S256',
            theme: 'login_form'
        };
        const arrayParams = [];
        for (var key in params) {
            if (!params.hasOwnProperty(key)) continue;
            arrayParams.push(`${key}=${params[key]}`);
        }
        const cv = authParams.codeVerifier;
        const stringParams = arrayParams.join('&');
        return cv + "@" + `https://accounts.nintendo.com/connect/1.0.0/authorize?${stringParams}`;
    });
}
