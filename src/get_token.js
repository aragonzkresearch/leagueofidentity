// usage:
// node get_token.js token  t n i_1 server1_addr:port ... i_t servert_addr:port month.year group 
// where token is the provider's token you get from the webpage, t and n are the parameters for the t out of n secret sharing and the following is the list of pairs consisting of indices and addresses (with ports) of the t servers to contact to get the shares needed to reconstruct the LoI token and month.year is field to request a token for the current month.year tag (setting month.year to "now") or to an old month.year tag, and group is a 0/1 flag to indicate whether the identity should be for thegroup (e.g., if the email is me@mycompany.com, if group=1 the identity will be set to mycompany.com).

const bls = require('@noble/curves/bls12-381');
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const bls_verify = require("@noble/curves/abstract/bls");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
var flag = 1;
var email, google, month, year;
var pk = [];
var hash = [];
var Q = [];
var lambda = [];
var date_path;
if (process.argv[5 + 2 * process.argv[3]] !== "now") {
    date_path = process.argv[5 + 2 * process.argv[3]];
    month = process.argv[5 + 2 * process.argv[3]].split('.')[0];
    year = process.argv[5 + 2 * process.argv[3]].split('.')[1];
} else date_path = "now";
var t = process.argv[3];
var group = process.argv[6 + 2 * process.argv[3]];
try {
    for (let i = 0; i < process.argv[3]; i++) {
        Q[i] = BigInt(process.argv[5 + 2 * i]);

        fetch(process.argv[6 + 2 * i] + "/" + group + "/" + date_path + "/" + process.argv[2]).then(function(response) {
            if (!response.ok) {
                console.log("Server " + process.argv[5 + 2 * i] + " (" + process.argv[6 + 2 * i] + ")" + " unavailable. Response status: " + response.status + ". Try later");
                process.exit(0);

            } else {
                response.text().then(function(text) {
                    console.log("Value received by server " + process.argv[5 + 2 * i] + " (" + process.argv[6 + 2 * i] + "): " + text);
                    if (!email) email = text.split('..')[2];
                    else if (text.split('..')[2] != email) throw ("Inconsistent values received from different servers");
                    if (!month) {
                        month = text.split('..')[3];
                    } else if (text.split('..')[3] != month) throw ("Inconsistent values received from different servers");
                    if (!year) year = text.split('..')[4];
                    else if (text.split('..')[4] != year) throw ("Inconsistent values received from different servers");
                    if (!google) google = text.split('..')[1];
                    else if (text.split('..')[1] != google) throw ("Inconsistent values received by different servers");

                    pk[Q[i]] = bls.bls12_381.G2.ProjectivePoint.fromHex(text.split('..')[5]);
                    hash[Q[i]] = bls.bls12_381.G1.ProjectivePoint.fromHex(text.split('..')[6]);
                    t--;
                    if (t == 0) Finalize();
                }).catch(function(err) {
                    console.log(err);
                });
            }

        });

    }

} catch (err) {

    console.log(err);
    process.exit(0);
}


function ComputeLagrangeCoefficients(lambda, t, Q) {
    const fp = mod.Field(bls.bls12_381.params.r);
    var tmp, I, J;


    for (let i = 0n; i < t; i++) {
        tmp = fp.create(1n);
        I = fp.create(Q[i]);
        for (let j = 0n; j < t; j++) {
            J = fp.create(Q[j]);
            if (j == i) continue;
            tmp = fp.mul(fp.div(J, fp.sub(J, I)), tmp);
        }
        lambda[Q[i]] = tmp;

    }

}

function Finalize() {
    ComputeLagrangeCoefficients(lambda, process.argv[3], Q);
    var tmp = bls.bls12_381.G2.ProjectivePoint.BASE.subtract(bls.bls12_381.G2.ProjectivePoint.BASE);
    var tmp2 = bls.bls12_381.G1.ProjectivePoint.BASE.subtract(bls.bls12_381.G1.ProjectivePoint.BASE);
    for (let i = 0n; i < process.argv[3]; i++) {
        pk[Q[i]] = pk[Q[i]].multiply(lambda[Q[i]]);
        hash[Q[i]] = hash[Q[i]].multiply(lambda[Q[i]]);
        tmp = tmp.add(pk[Q[i]]);
        tmp2 = tmp2.add(hash[Q[i]]);
    }
    var mpk = tmp;
    var token = tmp2;
    console.log("reconstructed master public key: " + mpk.toHex());
    const msg = hashes.utf8ToBytes("LoI.." + google + ".." + email + ".." + month + ".." + year);
    const h = bls.bls12_381.G1.hashToCurve(msg);
    const t1 = bls.bls12_381.pairing(h, mpk);
    const t2 = bls.bls12_381.pairing(token, bls.bls12_381.G2.ProjectivePoint.BASE);
    if (bls.bls12_381.fields.Fp12.eql(t1, t2) == false) {
        console.log("Verification of reconstructed token: failure.");
        return;
    }
    console.log("reconstructed token: " + token.toHex());
    console.log("Verification of reconstructed token: success.");
}