// usage:
// node server.js -p port -s share 

// NOTE: in a real world implementation, when req.params.anon==="1" in a fetch request the server should check
// whether the access token req.params.token has been previously issued and the user the access token refers to
// already received a valid crypto token in the same timeframe and reject the request in that case. 
// This is not done in the current demo.

const GOOGLE_CLIENT_ID = "525900358521-qqueujfcj3cth26ci3humunqskjtcm56.apps.googleusercontent.com";
const GOOGLE_API_KEY = ""; // fill it with your GOOGLE API KEY
const FACEBOOK_CLIENT_ID = "377291984666448";
const FACEBOOK_SECRET_ID = ""; // fill it with your FACEBOOK SECRET ID
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
const fs = require('fs');
const dic = require('./dic/loi_server_dic');
const loi_utils = require("./utils");
const bodyParser = require('body-parser');
const shell = require('shelljs');
commander
    .version('1.0.0', '-v, --version')
    .usage('-p <value> -s <value>')
    .requiredOption('-p, --port <value>', 'port on which to listen.')
    .requiredOption('-s, --share <value>', 'share of the master secret key.')
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

app.get('/:prov/:group/:date/:token/:friends/:anon', async (req, res) => {
    if (req.params.prov === "facebook" && req.params.friends === "null")
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
                            console.log("Received request for email: " + text2.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and anon param: " + req.params.anon);
                            var Email = text2.email;
                            if (req.params.anon === "1" && req.params.group === "0") Email = req.params.token;
                            else if (req.params.anon === "1" && req.params.group === "1") Email = req.params.token + "@" + text2.email.split('@')[1];
                            const st = ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon);
                            res.send(st);
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
                                    if (!text3.summary || !text3.summary.total_count || text3.summary.total_count < parseInt(req.params.friends)) {
                                        console.error("Invalid token request received by client.");
                                        res.sendStatus(400);
                                        return;

                                    }
                                    console.log("Received request for email: " + text2.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and friends param: " + req.params.friends + " and anon param: " + req.params.anon);
                                    var Email = text2.email;
                                    if (req.params.anon === "1" && req.params.group === "0") Email = req.params.token;
                                    else if (req.params.anon === "1" && req.params.group === "1") Email = req.params.token + "@" + text2.email.split('@')[1];
                                    const st = ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon);
                                    res.send(st);
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
                    fetch('https://people.googleapis.com/v1/people/' + text.sub + '?personFields=phoneNumbers&key=' + GOOGLE_API_KEY + '&access_token=' + req.params.token).then(function(response2) {
                        if (!response2.ok) {
                            console.error("Error. Response status: " + response.status);
                            res.sendStatus(400);
                            return;
                        }
                        response2.json().then(function(text2) {
                            console.log("Received request for phone number: " + text2.phoneNumbers[0].canonicalForm + " for provider: " + req.params.prov + " and anon param: " + req.params.anon);
                            var Email = text2.phoneNumbers[0].canonicalForm;
                            if (req.params.anon === "1") Email = req.params.token;
                            const st = ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon);
                            res.send(st);
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

                    console.log("Received request for email: " + text.email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and anon param: " + req.params.anon);
                    var Email = text.email;
                    if (req.params.anon === "1" && req.params.group === "0") Email = req.params.token;
                    else if (req.params.anon === "1" && req.params.group === "1") Email = req.params.token + "@" + text.email.split('@')[1];
                    const st = ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon);
                    res.send(st);
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

function ComputeTokenShare(email, share, month, year, group, provider, fetch_friends, anon) {
    try {
        console.log("token share to transmit to client: " + share);
        var share_decoded = utils.bytesToNumberBE(utils.hexToBytes(share));
        pk = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(share_decoded);
        if (group === "1" && anon === "0") email = email.split('@')[1];
        const msg = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + anon);
        var hash = bls.bls12_381.G1.hashToCurve(msg);
        hash = hash.multiply(share_decoded);
        return "LoI.." + provider + ".." + Buffer.from(email, 'utf8').toString('hex') + ".." + month + ".." + year + ".." + pk.toHex() + ".." + hash.toHex() + ".." + fetch_friends + ".." + anon;
    } catch (err) {

        console.error(err);
    }
}

app.use(bodyParser.raw({
    "type": "application/octet-stream"
}));

var counter = 0;
app.post('/dic/:date/:country/:anon/:age', function(req, res) {

    try {
        const tmpfilename = "./dic/" + req.params.country + "/tmp." + options.index + "." + counter++;
        const stream = fs.createWriteStream(tmpfilename);
        console.log("Received document written to file: " + tmpfilename);
        stream.once('open', function(fd) {
            stream.write(req.body);
            stream.end();
            console.log("Document is signed by SSN:");
            const SSN = shell.exec("./dic/" + req.params.country + "/verify.sh " + tmpfilename + " " + tmpfilename + ".challenge", {
                async: false
            }).stdout;
            console.log("\n");
            fs.readFile(tmpfilename + ".challenge", function(error, content) {
                if (error) {
                    res.send("ERROR");
                    return;
                }

                const data = JSON.parse(content);
                var flag = 0;
                for (let i = 0; i < data.Challenges.length; i++) {
                    if (dic.dic_map.get(data.Challenges[i].Challenge) === true && Math.floor(Date.now() / 1000) - data.Challenges[i].Challenge.split('.')[2] <= dic.TIMEOUT_CHALLENGE) {
                        flag = 1;
                    }
                }

                if (flag === 0) {
                    console.log("error");
                    res.send("ERROR");
                    return;

                }


                var year, month, curyear, curmnonth;
                const date = new Date();
                curyear = date.getFullYear();
                curmonth = date.getMonth();
                if (req.params.date !== "now") {
                    year = req.params.date.split('.')[1];
                    month = req.params.date.split('.')[0];
                    if (year > curyear || month > curmonth) {
                        console.error("Invalid token request received by client.");
                        res.send("ERROR");
                        return;
                    }
                } else {
                    year = curyear;
                    month = curmonth;
                }
                var st;
                const age = parseInt(SSN.split('/')[0].slice(6, 8));
                var requiredAge;
                if (req.params.age !== "null") {
                    requiredAge = parseInt(req.params.age);
                    if ((requiredAge < 0 && age > -requiredAge) || (requiredAge >= 0 && age < requiredAge)) {
                        console.error("Invalid token request received by client.");
                        res.send("ERROR");
                        return;

                    }
                }

                if (!req.params.anon || req.params.anon === "0") {
                    if (req.params.age !== "null") st = ComputeTokenShare(requiredAge + "@" + SSN.split('/')[0], options.share, month, year, "0", "dic." + req.params.country, "null", "0");
                    else st = ComputeTokenShare(SSN.split('/')[0], options.share, month, year, "0", "dic." + req.params.country, "null", "0");

                } else {
                    if (req.params.age !== "null") st = ComputeTokenShare(requiredAge + "@" + SSN.split('/')[1], options.share, month, year, "0", "dic." + req.params.country, "null", "1");
                    else st = ComputeTokenShare(SSN.split('/')[1], options.share, month, year, "0", "dic." + req.params.country, "null", "1");
                }

                console.log("DEBUG: sending " + st);
                res.send(st);


            });
        });


    } catch (err) {
        console.error(err);
    }

});