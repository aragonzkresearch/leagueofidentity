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