// usage:
// node server.js -p port -s share 

const GOOGLE_CLIENT_ID = "525900358521-qqueujfcj3cth26ci3humunqskjtcm56.apps.googleusercontent.com";
//const GOOGLE_API_KEY = ""; // fill it with your GOOGLE API KEY
const FACEBOOK_CLIENT_ID = "377291984666448";
//const FACEBOOK_SECRET_ID = ""; // fill it with your FACEBOOK SECRET ID
const FACEBOOK_SECRET_ID = "017c8e38a5677910096634717fd2a87e";
const GOOGLE_API_KEY = "AIzaSyBqocloBYO2vfatpC-RJ4-YMvU7fBNqgvQ"; // fill it with your GOOGLE API KEY
const bls = require("@noble/curves/bls12-381");
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

commander
    .version('1.0.0', '-v, --version')
    .usage('-p <value> -s <value>')
    .requiredOption('-p, --port <value>', 'port on which to listen.')
    .requiredOption('-s, --share <value>', 'share of the master secret key.')
    .parse(process.argv);

const options = commander.opts();
app.use(nocache());
app.use(cors());
app.listen(options.port, () => {
    console.log('listening on port ' + options.port);
});


app.get('/:prov/:group/:date/:token/:opts', async (req, res) => {
    if (req.params.prov === "facebook" && req.params.opts === "null")
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
                    fetch('https://graph.facebook.com/v18.0/me?fields=email&access_token=' + req.params.token).then(function(response2) {
                        response2.json().then(function(text2) {
                            if (!text2.email) {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;

                            }
                            console.log("Received request for email: " + text2.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group);
                            var st = ComputeTokenShare(text2.email, options.share, month, year, req.params.group, req.params.prov, req.params.opts);
                            res.send(st);
                        }).catch((err) => {
                            res.sendStatus(400);
                            console.error("Invalid token request received by client.");
                            return;
                        });
                    }).catch((err) => {
                        res.sendStatus(400);
                        console.error("Invalid token request received by client.");
                        return;
                    });
                } else {
                    res.sendStatus(400);
                    console.error("Invalid token request received by client.");
                    return;
                }
            }).catch(function(err) {
                res.sendStatus(400);
                console.error("Invalid token request received by client.");
                return;
            });
        }).catch(function(err) {
            res.sendStatus(400);
            console.error("Invalid token request received by client.");
            return;
        });
    else if (req.params.prov === "facebook" && req.params.opts !== "null")
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
                    fetch('https://graph.facebook.com/v18.0/me?fields=email&access_token=' + req.params.token).then(function(response2) {
                        response2.json().then(function(text2) {
                            if (!text2.email) {
                                console.error("Invalid token request received by client.");
                                res.sendStatus(400);
                                return;

                            }
                            fetch('https://graph.facebook.com/v18.0/me/friends?access_token=' + req.params.token).then(function(response3) {
                                response3.json().then(function(text3) {
                                    if (!text3.summary || !text3.summary.total_count || text3.summary.total_count < parseInt(req.params.opts)) {
                                        console.error("Invalid token request received by client.");
                                        res.sendStatus(400);
                                        return;

                                    }
                                    console.log("Received request for email: " + text2.email + " for provider: " + req.params.prov + " with option " + req.params.opts + " and group flag: " + req.params.group);
                                    var st = ComputeTokenShare(text2.email, options.share, month, year, req.params.group, req.params.prov, req.params.opts);
                                    res.send(st);
                                }).catch((err) => {
                                    res.sendStatus(400);
                                    console.error("Invalid token request received by client.");
                                    return;
                                });
                            }).catch((err) => {
                                res.sendStatus(400);
                                console.error("Invalid token request received by client.");
                                return;
                            });
                        }).catch((err) => {
                            res.sendStatus(400);
                            console.error("Invalid token request received by client.");
                            return;
                        });
                    }).catch((err) => {
                        res.sendStatus(400);
                        console.error("Invalid token request received by client.");
                        return;
                    });
                } else {
                    res.sendStatus(400);
                    console.error("Invalid token request received by client.");
                    return;
                }
            }).catch(function(err) {
                res.sendStatus(400);
                console.error("Invalid token request received by client.");
                return;
            });
        }).catch(function(err) {
            res.sendStatus(400);
            console.error("Invalid token request received by client.");
            return;
        });
    else if (req.params.prov === "google.phone" && req.params.group !== "0")
        fetch('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=' + req.params.token)
        .then(function(response) {
            if (!response.ok) {
                console.error("Error. Response status: " + response.status);
                res.sendStatus(400);
                return;
            }
            response.json().then(function(text) {
                if (!text.azp || text.azp != GOOGLE_CLIENT_ID) {
                    res.sendStatus(400);
                    console.error("Token request with invalid client id.");
                    return;

                }
                if (text.email_verified && text.email_verified === 'true') {
                    var year, month, curyear, curmnonth;
                    const date = new Date();
                    curyear = date.getFullYear();
                    curmonth = date.getMonth();
                    if (req.params.date !== "now") {
                        year = req.params.date.split('.')[1];
                        month = req.params.date.split('.')[0];
                        if (year > curyear || month > curmonth) {
                            res.sendStatus(400);
                            console.error("Invalid token request received by client.");
                            return;
                        }
                    } else {
                        year = curyear;
                        month = curmonth;
                    }
                    fetch('https://people.googleapis.com/v1/people/' + text.sub + '?personFields=phoneNumbers&key=' + GOOGLE_API_KEY + '&access_token=' + req.params.token).then(function(response2) {
                        if (!response2.ok) {
                            console.error("Error. Response status: " + response.status);
                            res.sendStatus(400);
                            return;
                        }
                        response2.json().then(function(text2) {
                            console.log("Received request for phone number: " + text2.phoneNumbers[0].canonicalForm + " for provider: " + req.params.prov);
                            var st = ComputeTokenShare(text2.phoneNumbers[0].canonicalForm, options.share, month, year, req.params.group, req.params.prov, req.params.opts);
                            res.send(st);
                        }).catch(function(err) {
                            res.sendStatus(400);
                            console.error("Invalid token request received by client.");
                            return;
                        });
                    }).catch(function(err) {
                        res.sendStatus(400);
                        console.error("Invalid token request received by client.");
                        return;
                    });
                } else {
                    res.sendStatus(400);
                    console.error("Invalid token request received by client.");
                    return;
                }
            }).catch(function(err) {
                res.sendStatus(400);
                console.error("Invalid token request received by client.");
                return;
            });
        }).catch(function(err) {
            res.sendStatus(400);
            console.error("Invalid token request received by client.");
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
                    res.sendStatus(400);
                    console.error("Token request with invalid client id.");
                    return;

                }
                if (text.email_verified && text.email_verified === 'true') {
                    var year, month, curyear, curmnonth;
                    const date = new Date();
                    curyear = date.getFullYear();
                    curmonth = date.getMonth();
                    if (req.params.date !== "now") {
                        year = req.params.date.split('.')[1];
                        month = req.params.date.split('.')[0];
                        if (year > curyear || month > curmonth) {
                            res.sendStatus(400);
                            console.error("Invalid token request received by client.");
                            return;
                        }
                    } else {
                        year = curyear;
                        month = curmonth;
                    }

                    console.log("Received request for email: " + text.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group);
                    var st = ComputeTokenShare(text.email, options.share, month, year, req.params.group, req.params.prov, req.params.opts);
                    res.send(st);
                } else {
                    res.sendStatus(400);
                    console.error("Invalid token request received by client.");
                    return;
                }
            }).catch(function(err) {
                res.sendStatus(400);
                console.error("Invalid token request received by client.");
                return;
            });
        }).catch(function(err) {
            res.sendStatus(400);
            console.error("Invalid token request received by client.");
            return;
        });
    else {
        console.error("Error. Request for unsupported or unkown provider.");
        res.sendStatus(400);
        return;
    }
});

function ComputeTokenShare(email, share, month, year, group, provider, fetch_opts) {
    try {
        console.log("token share to transmit to client: " + share);
        var share_decoded = utils.bytesToNumberBE(utils.hexToBytes(share));
        pk = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(share_decoded);
        if (group === "1") email = email.split('@')[1];
        const msg = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_opts);
        var hash = bls.bls12_381.G1.hashToCurve(msg);
        //hash=bls.bls12_381.G1.ProjectivePoint.BASE;
        hash = hash.multiply(share_decoded);
        return "LoI.." + provider + ".." + Buffer.from(email, 'utf8').toString('hex') + ".." + month + ".." + year + ".." + pk.toHex() + ".." + hash.toHex() + ".." + fetch_opts;
    } catch (err) {

        console.error(err);
    }
}
