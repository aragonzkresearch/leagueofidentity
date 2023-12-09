// usage:
// node server.js port share

// TODO: in real apps the server should check
// that the token is with respect to the same client ID for which it should be
// Concretely, check that the 'azp' field returned by the verification endpoint equals the client ID in main.js

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

app.use(nocache());
app.use(cors());
app.listen(process.argv[2], () => {
    console.log('listening on port ' + process.argv[2]);
});

app.get('/:group/:date/:token', async (req, res) => {

    try {
        fetch('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=' + req.params.token)
            .then(function(response) {
                if (!response.ok) {
                    console.log("Error. Response status: " + response.status);
                    res.sendStatus(400);
                    return;
                }
                response.json().then(function(text) {
                    if (text.email_verified && text.email_verified === 'true') {
var year,month,curyear,curmnonth;
const date=new Date();
curyear=date.getFullYear();
curmonth=date.getMonth();
if (req.params.date!=="now")
{
year=req.params.date.split('.')[1];
month=req.params.date.split('.')[0];
if (year>curyear || month>curmonth){
                    res.sendStatus(400);
 console.log("Invalid token request received by client.");
return;
}
} else{
year=curyear;
month=curmonth;
}

                        var st = ComputeTokenShare(text.email, process.argv[3],month,year,req.params.group);
                        res.send(st);
                    } else
                        res.sendStatus(400);
                }).catch(function(err) {
                    res.sendStatus(400);
                });
            });
    } catch (err) {
        console.log(err);
    }


});

function ComputeTokenShare(email, share,month,year,group) {
    try {
        console.log("share:" + share);
        var share_decoded = utils.bytesToNumberBE(utils.hexToBytes(share));
        pk = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(share_decoded);
if (group==="1") email=email.split('@')[1];
        const msg = hashes.utf8ToBytes("LoI..google.." + email + ".." + month + ".." + year);
        var hash = bls.bls12_381.G1.hashToCurve(msg);
        //hash=bls.bls12_381.G1.ProjectivePoint.BASE;
        hash = hash.multiply(share_decoded);
        return "LoI..google.." + email + ".." + month + ".." + year + ".." + pk.toHex() + ".." + hash.toHex();
    } catch (err) {

        console.log(err);
    }
}
