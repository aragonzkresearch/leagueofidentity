// usage:
// node server.js -p port -s share 
// the  configuration file is in config.json 
// NOTE: in a real world implementation, when req.params.anon==="1" in a fetch request the server should check
// whether the access token req.params.token has been previously issued and the user the access token refers to
// already received a valid crypto token in the same timeframe and reject the request in that case.
// Moreover, in this case it is easy to see that one should require threshold t>= n/2 +1.
// This is not done in the current demo.

// The file params.json contains configuration directive, in particular here we will use GOOGLE_CLIENT_ID, FACEBOOK_CLIENT_ID, GOOGLE_API_KEY and FACEBOOK_SECRET_ID
// Note: The providers google, facebook, and google.phone are handled in this file while dic.* and eth are handled in separated files

const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const express = require('express');
const app = express();
const nocache = require('nocache');
const cors = require('cors');
const commander = require('commander');
const dic = require('./dic/loi_server_dic');
const loi_utils = require("./utils");
const cts = require("./compute_token_share");
const eth_provider = require("./eth_provider/loi_server_eth");
const nintendo_provider = require("./nintendo_provider/loi_server_nintendo");
const bodyParser = require('body-parser');
const fs = require('fs');
commander
    .version('1.0.0', '-v, --version')
    .usage('-p <value> -s <value>')
    .requiredOption('-p, --port <value>', 'port on which to listen.')
    .requiredOption('-s, --share <value>', 'file containing the share of the master secret key.')
    .requiredOption('-i, --index <value>', 'index of the server. This option is necessary to deal with digital identity cards (DICs) authentication.')
    .parse(process.argv);

const options = commander.opts();
app.use(nocache());
app.use(cors());
app.listen(options.port, () => {
    console.log('listening on port ' + options.port);
});

app.use(bodyParser.urlencoded({
    extended: false
}));


loi_utils.read(fs.createReadStream("params.json")).then(function(JsonContent) {
    const data = JSON.parse(JsonContent);
    const TIMEOUT_CHALLENGE = data.params.TIMEOUT_CHALLENGE;
    const GOOGLE_CLIENT_ID = data.params.GOOGLE_CLIENT_ID;
    const GOOGLE_API_KEY = data.params.GOOGLE_API_KEY;
    const FACEBOOK_CLIENT_ID = data.params.FACEBOOK_CLIENT_ID;
    const FACEBOOK_SECRET_ID = data.params.FACEBOOK_SECRET_ID;
    const INFURA_API_KEY = data.params.INFURA_API_KEY;
    const SignMessage = data.params.SignMessage;
    loi_utils.read(fs.createReadStream(options.share)).then(function(Msg) {
        options.share = Msg;
        app.get('/:prov/:group/:date/:token/:friends/:anon/:ethereum', async (req, res) => {
            if (req.params.prov === "nintendo") {
                nintendo_provider.loi_server_nintendo(req, res, options);
                return;
            } else if (req.params.prov === "eth") {
                eth_provider.loi_server_eth(req, res, TIMEOUT_CHALLENGE, INFURA_API_KEY, SignMessage, options);
                return;
            } else if (req.params.prov === "facebook" && req.params.friends === "null")
                fetch('https://graph.facebook.com/v18.0/debug_token?input_token=' + req.params.token + '&access_token=' + FACEBOOK_CLIENT_ID + '|' + FACEBOOK_SECRET_ID)
                .then(function(response) {
                    if (!response.ok) {
                        console.error("Error. Response status: " + response.status);
                        res.sendStatus(400);
                        return;
                    }
                    response.json().then(function(text) {
                        if (!text.data || !text.data.app_id || text.data.app_id != FACEBOOK_CLIENT_ID) {
                            console.error("Token request with invalid client id.");
                            res.sendStatus(400);
                            return;

                        }
                        if (text.data && text.data.is_valid && text.data.is_valid === true) {
                            var year, month;
                            const date = loi_utils.handleDate(req.params.date);

                            if (date === 'null') {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            } else {
                                year = date.year;
                                month = date.month;
                            }

                            fetch('https://graph.facebook.com/v18.0/me?fields=email&access_token=' + req.params.token).then(function(response2) {
                                response2.json().then(function(text2) {
                                    if (!text2.email) {
                                        console.error("Invalid token request received by client.");
                                        res.sendStatus(400);
                                        return;

                                    }
                                    console.log("Received request for email: " + text2.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and anon param: " + req.params.anon + " and ethereum mode: " + req.params.ethereum);
                                    var Email = text2.email;
                                    if (req.params.anon === "1" && req.params.group === "0") Email = utils.bytesToHex(sha256.sha56(req.params.token));
                                    else if (req.params.anon === "1" && req.params.group === "1") Email = utils.bytesToHex(sha256.sha256(req.params.token)) + "@" + text2.email.split('@')[1];
                                    const st = cts.ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon, req.params.ethereum);
                                    if (req.params.ethereum === 'null')
                                        res.send(st);
                                    else st.then(function(ShareToken) {
                                        res.send(ShareToken);
                                    });
                                }).catch((err) => {
                                    console.error("Invalid token request received by client.");
                                    res.sendStatus(400);
                                    return;
                                });
                            }).catch((err) => {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            });
                        } else {
                            console.error("Invalid token request received by client.");
                            res.sendStatus(400);
                            return;
                        }
                    }).catch(function(err) {
                        console.error("Invalid token request received by client.");
                        res.sendStatus(400);
                        return;
                    });
                }).catch(function(err) {
                    console.error("Invalid token request received by client.");
                    res.sendStatus(400);
                    return;
                });
            else if (req.params.prov === "facebook" && req.params.friends !== "null")
                fetch('https://graph.facebook.com/v18.0/debug_token?input_token=' + req.params.token + '&access_token=' + FACEBOOK_CLIENT_ID + '|' + FACEBOOK_SECRET_ID)
                .then(function(response) {
                    if (!response.ok) {
                        console.error("Error. Response status: " + response.status);
                        res.sendStatus(400);
                        return;
                    }
                    response.json().then(function(text) {
                        if (!text.data || !text.data.app_id || text.data.app_id != FACEBOOK_CLIENT_ID) {
                            console.error("Token request with invalid client id.");
                            res.sendStatus(400);
                            return;

                        }
                        if (text.data && text.data.is_valid && text.data.is_valid === true) {
                            var year, month;
                            const date = loi_utils.handleDate(req.params.date);

                            if (date === 'null') {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            } else {
                                year = date.year;
                                month = date.month;
                            }

                            fetch('https://graph.facebook.com/v18.0/me?fields=email&access_token=' + req.params.token).then(function(response2) {
                                response2.json().then(function(text2) {
                                    if (!text2.email) {
                                        console.error("Invalid token request received by client.");
                                        res.sendStatus(400);
                                        return;

                                    }
                                    fetch('https://graph.facebook.com/v18.0/me/friends?access_token=' + req.params.token).then(function(response3) {
                                        response3.json().then(function(text3) {
                                            if (!text3.summary || !text3.summary.total_count || text3.summary.total_count < parseInt(req.params.friends)) {
                                                console.error("Invalid token request received by client.");
                                                res.sendStatus(400);
                                                return;

                                            }
                                            console.log("Received request for email: " + text2.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and friends param: " + req.params.friends + " and anon param: " + req.params.anon + " and ethereum mode: " + req.params.ethereum);
                                            var Email = text2.email;
                                            if (req.params.anon === "1" && req.params.group === "0") Email = utils.bytesToHex(sha256.sha256(req.params.token));
                                            else if (req.params.anon === "1" && req.params.group === "1") Email = utils.bytesToHex(sha256.sha256(req.params.token)) + "@" + text2.email.split('@')[1];
                                            const st = cts.ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon, req.params.ethereum);
                                            if (req.params.ethereum === 'null')
                                                res.send(st);
                                            else st.then(function(ShareToken) {
                                                res.send(ShareToken);
                                            });
                                        }).catch((err) => {
                                            console.error("Invalid token request received by client.");
                                            res.sendStatus(400);
                                            return;
                                        });
                                    }).catch((err) => {
                                        console.error("Invalid token request received by client.");
                                        res.sendStatus(400);
                                        return;
                                    });
                                }).catch((err) => {
                                    console.error("Invalid token request received by client.");
                                    res.sendStatus(400);
                                    return;
                                });
                            }).catch((err) => {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            });
                        } else {
                            console.error("Invalid token request received by client.");
                            res.sendStatus(400);
                            return;
                        }
                    }).catch(function(err) {
                        console.error("Invalid token request received by client.");
                        res.sendStatus(400);
                        return;
                    });
                }).catch(function(err) {
                    console.error("Invalid token request received by client.");
                    res.sendStatus(400);
                    return;
                });
            else if (req.params.prov === "google.phone" && req.params.group !== "1")
                fetch('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=' + req.params.token)
                .then(function(response) {
                    if (!response.ok) {
                        console.error("Error. Response status: " + response.status);
                        res.sendStatus(400);
                        return;
                    }
                    response.json().then(function(text) {
                        if (!text.azp || text.azp != GOOGLE_CLIENT_ID) {
                            console.error("Token request with invalid client id.");
                            res.sendStatus(400);
                            return;

                        }
                        if (text.email_verified && text.email_verified === 'true') {
                            var year, month;
                            const date = loi_utils.handleDate(req.params.date);

                            if (date === 'null') {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            } else {
                                year = date.year;
                                month = date.month;
                            }

                            fetch('https://people.googleapis.com/v1/people/' + text.sub + '?personFields=phoneNumbers&key=' + GOOGLE_API_KEY + '&access_token=' + req.params.token).then(function(response2) {
                                if (!response2.ok) {
                                    console.error("Error. Response status: " + response.status);
                                    res.sendStatus(400);
                                    return;
                                }
                                response2.json().then(function(text2) {
                                    console.log("Received request for phone number: " + text2.phoneNumbers[0].canonicalForm + " for provider: " + req.params.prov + " and anon param: " + req.params.anon + " and ethereum mode: " + req.params.ethereum);
                                    var Email = text2.phoneNumbers[0].canonicalForm;
                                    if (req.params.anon === "1") Email = utils.bytesToHex(sha256.sha256(req.params.token));
                                    const st = cts.ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon, req.params.ethereum);
                                    if (req.params.ethereum === 'null')
                                        res.send(st);
                                    else st.then(function(ShareToken) {
                                        res.send(ShareToken);
                                    });
                                }).catch(function(err) {
                                    console.error("Invalid token request received by client.");
                                    res.sendStatus(400);
                                    return;
                                });
                            }).catch(function(err) {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            });
                        } else {
                            console.error("Invalid token request received by client.");
                            res.sendStatus(400);
                            return;
                        }
                    }).catch(function(err) {
                        console.error("Invalid token request received by client.");
                        res.sendStatus(400);
                        return;
                    });
                }).catch(function(err) {
                    console.error("Invalid token request received by client.");
                    res.sendStatus(400);
                    return;
                });

            else if (req.params.prov === "google")
                fetch('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=' + req.params.token)
                .then(function(response) {
                    if (!response.ok) {
                        console.error("Error. Response status: " + response.status);
                        res.sendStatus(400);
                        return;
                    }
                    response.json().then(function(text) {
                        if (!text.azp || text.azp != GOOGLE_CLIENT_ID) {
                            console.error("Token request with invalid client id.");
                            res.sendStatus(400);
                            return;

                        }
                        if (text.email_verified && text.email_verified === 'true') {
                            var year, month;
                            const date = loi_utils.handleDate(req.params.date);

                            if (date === 'null') {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;
                            } else {
                                year = date.year;
                                month = date.month;
                            }

                            console.log("Received request for email: " + text.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and anon param: " + req.params.anon + " and ethereum mode: " + req.params.ethereum);
                            var Email = text.email;
                            if (req.params.anon === "1" && req.params.group === "0") Email = utils.bytesToHex(sha256.sha256(req.params.token));
                            else if (req.params.anon === "1" && req.params.group === "1") Email = utils.bytesToHex(sha256.sha256(req.params.token)) + "@" + text.email.split('@')[1];
                            const st = cts.ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon, req.params.ethereum);
                            if (req.params.ethereum === 'null')
                                res.send(st);
                            else st.then(function(ShareToken) {
                                res.send(ShareToken);
                            });
                        } else {
                            console.error("Invalid token request received by client.");
                            res.sendStatus(400);
                            return;
                        }
                    }).catch(function(err) {
                        console.error("Invalid token request received by client.");
                        res.sendStatus(400);
                        return;
                    });
                }).catch(function(err) {
                    console.error("Invalid token request received by client.");
                    res.sendStatus(400);
                    return;
                });
            else if (loi_utils.prov_is_dic(req.params.prov)) dic.loi_server_dic(options.index, req, res);
            else {
                console.error("Error. Request for unsupported or unkown provider.");
                res.sendStatus(400);
                return;
            }
        });


        app.use(bodyParser.raw({
            "type": "application/octet-stream"
        }));

        app.post('/dic/:date/:country/:anon/:age/:cross_country/:ethereum', function(req, res) {
            if (req.params.country === "it")
                dic.loi_server_post_it(options, req, res);
            else {
                console.error("Error. Request for unsupported or unkown provider.");
                res.sendStatus(400);

            }

        });

    });
});