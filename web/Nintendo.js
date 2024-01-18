function generateRandom(length) {
    return btoa(crypto.getRandomValues(new Uint8Array(length)));
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
    codeVerifier = "P_osxJeP2y9G6ySkkrUoancYztkdrPzi_edBY12Dt9U"; // use it for debug
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
            redirect_uri: 'npf71b963c1b7b6d119://auth&client_id=71b963c1b7b6d119',
            scope: 'openid%20user%20user.birthday%20user.mii%20user.screenName',
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
