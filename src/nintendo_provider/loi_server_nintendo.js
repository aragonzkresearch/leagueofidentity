const fs = require('fs');
const request2 = require('request-promise-native');
const loi_utils = require('../utils');
const jar = request2.jar();
const request = request2.defaults({
    jar: jar
});
const cts = require("../compute_token_share");

async function getSessionToken(session_token_code, codeVerifier, nsoVersion) {
    const resp = await request({
        method: 'POST',
        uri: 'https://accounts.nintendo.com/connect/1.0.0/api/session_token',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Platform': 'Android',
            'X-ProductVersion': nsoVersion,
            'User-Agent': `OnlineLounge/${nsoVersion} NASDKAPI Android`
        },
        form: {
            client_id: '71b963c1b7b6d119',
            session_token_code: session_token_code,
            //        session_token_code: "eyJhbGciOiJIUzI1NiJ9.eyJzdGM6YyI6IkxOZnVYaVdzdXJnU0RjbXdqRS1MNUkyUGpYVEg0UTl4NU5DNUstNzNXQTgiLCJhdWQiOiI3MWI5NjNjMWI3YjZkMTE5IiwiaWF0IjoxNzA1NTc3MTMyLCJqdGkiOiI5MDU2OTc4MDE3NCIsInN0YzptIjoiUzI1NiIsInN1YiI6IjExZWM5MGRmNDY5M2Y0YTUiLCJzdGM6c2NwIjpbMCw4LDksMTcsMjNdLCJ0eXAiOiJzZXNzaW9uX3Rva2VuX2NvZGUiLCJpc3MiOiJodHRwczovL2FjY291bnRzLm5pbnRlbmRvLmNvbSIsImV4cCI6MTcwNTU3NzczMn0.e0oZpDjKJNGjotHjA14CedVnPdTJdj9vgy7DrIFZa0Q",
            session_token_code_verifier: codeVerifier
            //           session_token_code_verifier: "S_osxJeP2y9G6ySkkrUoancYztkdrPzi_edBY12Dt9U"
        },
        json: true
    });

    return resp.session_token;
}

async function getApiToken(Session_Token, nsoVersion, userAgentString) {
    const resp = await request({
        method: 'POST',
        uri: 'https://accounts.nintendo.com/connect/1.0.0/api/token',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Platform': 'Android',
            'X-ProductVersion': nsoVersion,
            'User-Agent': userAgentString,
            //           'Host': 'api-lp1.znc.srv.nintendo.net',
            'Host': 'accounts.nintendo.com',
            'Accept-Language': 'en-US',
            'Accept': 'application/json',
            'Connection': 'Keep-Alive',
            'Authorization': 'Bearer',
            'Accept-Encoding': 'gzip'
        },
        json: {
            client_id: '71b963c1b7b6d119',
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer-session-token',
            session_token: Session_Token
        }
    });
    return {
        id: resp.id_token,
        access: resp.access_token
    };
}

async function getUserInfo(token, nsoVersion, userAgentString) {
    const response = await request({
        method: 'GET',
        uri: 'https://api.accounts.nintendo.com/2.0.0/users/me',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Platform': 'Android',
            'X-ProductVersion': nsoVersion,
            'User-Agent': userAgentString,
            Authorization: `Bearer ${token}`
        },
        json: true
    });

    return {
        id: response.id,
        emailVerified: response.emailVerified
    };
}

function loi_server_nintendo(req, res, options) {
    try {
        if (req.params.group === "1") {
            console.error("Token request with group param 1 for provider nintendo.");
            res.sendStatus(400);
            return;
        }
        if (req.params.anon === "1") {
            console.error("Token request with anon param 1 for provider nintendo.");
            res.sendStatus(400);
            return;
        }
        if (req.params.friends !== "null") {
            console.error("Token request with non-null friends param for provider nintendo.");
            res.sendStatus(400);
            return;
        }
        const codeVerifier = req.params.token.split('@')[0];
        const SessionTokenCode = req.params.token.split('@')[1];
        loi_utils.read(fs.createReadStream("./params.json")).then(function(JsonContent) {
            const data = JSON.parse(JsonContent);
            const nsoVersion = data.params.nsoVersion;
            const userAgentString = `com.nintendo.znca/${nsoVersion} (Android/7.1.2)`;
            getSessionToken(SessionTokenCode, codeVerifier, nsoVersion).then(function(SessionToken) {
                //    console.log("got st:" + SessionToken);
                getApiToken(SessionToken, nsoVersion, userAgentString).then(function(apiTokens) {
                    //      console.log("got apitok:" + apiTokens.id + " " + apiTokens.access);
                    getUserInfo(apiTokens.access, nsoVersion, userAgentString).then(function(UserInfo) {
                        if (UserInfo.emailVerified !== true) {
                            console.error("Token request for an account with non-verified email. Refusing the request.");
                            res.sendStatus(400);
                            return;
                        }
                        const Email = UserInfo.id;

                        console.log("Received request for email: " + Email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and friends param: " + req.params.friends + " and anon param: " + req.params.anon + " and ethereum mode: " + req.params.ethereum);
                        var year, month, curyear, curmnonth;
                        const date = new Date();
                        curyear = date.getFullYear();
                        curmonth = date.getMonth();
                        if (req.params.date !== "now") {
                            year = req.params.date.split('.')[1];
                            month = req.params.date.split('.')[0];
                            if (year > curyear || month > curmonth) {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            }
                        } else {
                            year = curyear;
                            month = curmonth;
                        }
                        const st = cts.ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon, req.params.ethereum);
                        res.send(st);
                    }).catch(function(err) {
                        console.error("Invalid token request received by client." + err);
                        res.sendStatus(400);
                        return;

                    });
                }).catch(function(err) {
                    console.error("Invalid token request received by client2." + err);
                    res.sendStatus(400);
                    return;
                });
            }).catch(function(err) {
                console.error("Invalid token request received by client3." + err);
                res.sendStatus(400);
                return;
            });
        }).catch(function(err) {
            console.error("Invalid token request received by client3." + err);
            res.sendStatus(400);
            return;
        });
    } catch (err) {
        console.error("Invalid token request received by client.");
        res.sendStatus(400);
        return;
    }



}


module.exports = {
    loi_server_nintendo,
}
