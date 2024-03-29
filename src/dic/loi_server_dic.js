const bls = require("@noble/curves/bls12-381"); // NOTE: this use of bls require does not depend on Ethereum mode. 
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const utils = require("@noble/curves/abstract/utils");
const fs = require('fs');
const shell = require('shelljs');
const mod = require("@noble/curves/abstract/modular");
const cts = require('../compute_token_share');
const loi_utils = require('../utils');
const dic_map = new Map();


// The file params.json contains configuration directive, in particular here we will use TIMEOUT_CHALLENGE for the digital identity card module and DIC_IT_AGE_LIMIT 

function loi_server_dic(index, req, res) {
    dic_map.set("2.073e239b424905855426d8daad7ca69e944a902b633fc4d314cf10b65594ed4b.1703668410", true);
    dic_map.set("3.66cdfbb18ab5edc73a61b48a34a2034545dd3c8209beeddd48d9bbf44d2ae3f2.1703716227", true);
    const challenge = index + "." + utils.bytesToHex(bls.bls12_381.utils.randomPrivateKey()) + "." + Math.floor(Date.now() / 1000);
    //   var challenge;
    // if (index === "2") challenge = "2.229e58ed87e70adf74001e2943751723f35c7a5febb2440ff5d66689f580ea46.1703892168";
    // if (index === "3") challenge = "3.578edb265928f79b56b2ffd79a3237a66d420b155d5b8206236adba4adf675bf.1703892168";
    dic_map.set(challenge, true);
    res.send(challenge);
}

var counter = 0;

function loi_server_post_it(options, req, res) { // for Italian DIC
    try {
        loi_utils.read(fs.createReadStream("./params.json")).then(function(JsonContent) {
            const data = JSON.parse(JsonContent);
            const TIMEOUT_CHALLENGE = data.params.TIMEOUT_CHALLENGE;
            const AGE_LIMIT = data.params.DIC_IT_AGE_LIMIT;
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
                        if (dic_map.get(data.Challenges[i].Challenge) === true && Math.floor(Date.now() / 1000) - data.Challenges[i].Challenge.split('.')[2] <= TIMEOUT_CHALLENGE) {
                            flag = 1;
                        }
                    }

                    if (flag === 0) {
                        console.log("error");
                        res.send("ERROR");
                        return;

                    }


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

                    var st;
                    if (req.params.cross_country !== "null") req.params.country = "";
                    else req.params.country = "." + req.params.country;
                    var age = parseInt(SSN.split('/')[0].slice(6, 8));
                    if (age < AGE_LIMIT) age = 2000 + age;
                    else age = 1900 + age;
                    var requiredAge;
                    if (req.params.age !== "null") {
                        requiredAge = parseInt(req.params.age);

                        if (requiredAge > 0) {
                            if (requiredAge < AGE_LIMIT) requiredAge = 2000 + requiredAge;
                            else requiredAge = 1900 + requiredAge;
                        } else {
                            if (-requiredAge < AGE_LIMIT) requiredAge = -(2000 - requiredAge);
                            else requiredAge = -(1900 - requiredAge);

                        }
                        if ((requiredAge < 0 && age > -requiredAge) || (requiredAge >= 0 && age < requiredAge)) {
                            console.error("Invalid token request received by client.");
                            res.send("ERROR");
                            return;

                        }
                    }

                    if (!req.params.anon || req.params.anon === "0") {
                        if (req.params.age !== "null") st = cts.ComputeTokenShare(requiredAge + "@" + SSN.split('/')[0], options.share, month, year, "0", "dic" + req.params.country, "null", "0", req.params.ethereum);
                        else st = cts.ComputeTokenShare(SSN.split('/')[0], options.share, month, year, "0", "dic" + req.params.country, "null", "0", req.params.ethereum);

                    } else {
                        if (req.params.age !== "null") st = cts.ComputeTokenShare(requiredAge + "@" + SSN.split('/')[1], options.share, month, year, "0", "dic" + req.params.country, "null", "1", req.params.ethereum);
                        else st = cts.ComputeTokenShare(SSN.split('/')[1], options.share, month, year, "0", "dic" + req.params.country, "null", "1", req.params.ethereum);
                    }

                    console.log("DEBUG: sending " + st);
                    res.send(st);


                });
            });
        });

    } catch (err) {
        console.error(err);
    }



}

module.exports = {
    loi_server_dic,
    loi_server_post_it,
    dic_map,
}