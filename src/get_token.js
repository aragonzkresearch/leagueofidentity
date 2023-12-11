// usage:
// node get_token.js -A access_token  -t t -n n -l i_1 server1_addr:port ... i_t servert_addr:port month.year -g  
// where token is the provider's token you get from the webpage, t and n are the parameters for the t out of n secret sharing and the following is the list of pairs consisting of indices and addresses (with ports) of the t servers to contact to get the shares needed to reconstruct the LoI token and month.year is field to request a token for the current month.year tag (setting month.year to "now") or to an old month.year tag, and group is a 0/1 flag to indicate whether the identity should be for thegroup (e.g., if the email is me@mycompany.com, if group=1 the identity will be set to mycompany.com).

const bls = require('@noble/curves/bls12-381');
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const bls_verify = require("@noble/curves/abstract/bls");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const commander = require('commander');

commander
    .version('1.0.0', '-v, --version')
    .usage('-A <value> -t <value> -n <value> -l list [OPTIONS]')
    .requiredOption('-A, --access_token <value>', 'access token.')
    .requiredOption('-t, --threshold <value>', 'threshold of nodes required to reconstruct the master secret key.')
    .requiredOption('-n, --no_nodes <value>', 'total number of nodes.')
    .requiredOption('-l, --list <value...>', 'list of t values of the form i_1 server_1:port_1 ... i_t server_t:port_t, where t is the given threshold specified by the -t argument and each index i_1, ..., i_t is an integer between 1 and n, where n is the value specified by the -n argument.')
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-g, --group', 'request a group token.')
    .option('-P, --provider <value>', 'provider (currently only \"google\" is supported).')
    .parse(process.argv);

const options = commander.opts();
var provider;
if (options.provider && options.provider !== "google") {
    console.error("Supported providers: google.");
    process.exit(1);
} else provider = "google";
if (options.list.length != options.threshold * 2) {
    commander.help({
        error: true
    });
    return;
}
var Indices = [];
var Addresses = [];
for (let i = 0; i < options.threshold; i++) {
    let k = parseInt(options.list[i * 2]);
    if (k > options.no_nodes || k < 1) {
        commander.help({
            error: true
        });
        return;
    }
    Indices[i] = options.list[i * 2];
    Addresses[i] = options.list[i * 2 + 1];
}
const group = !options.group ? "0" : "1";
const Month = !options.month ? "now" : options.month; // Month is "now" or a string of the form month.year with month between 0 and 11 and year of the form XXXX
var flag = 1;
var email, Provider, month, year;
var pk = [];
var hash = [];
var Q = [];
var lambda = [];
var date_path;
//if (process.argv[5 + 2 * process.argv[3]] !== "now") {
if (Month !== "now") {
    // date_path = process.argv[5 + 2 * process.argv[3]];
    // month = process.argv[5 + 2 * process.argv[3]].split('.')[0];
    // year = process.argv[5 + 2 * process.argv[3]].split('.')[1];
    date_path = Month;
    month = Month.split('.')[0];
    year = Month.split('.')[1];
} else date_path = "now";
//var t = process.argv[3];
var t = options.threshold;
//var group = process.argv[6 + 2 * process.argv[3]];
try {
    //for (let i = 0; i < process.argv[3]; i++) {
    for (let i = 0; i < options.threshold; i++) {
        //Q[i] = BigInt(process.argv[5 + 2 * i]);
        Q[i] = BigInt(Indices[i]);

        //fetch(process.argv[6 + 2 * i] + "/" + group + "/" + date_path + "/" + process.argv[2]).then(function(response) {
        fetch(Addresses[i] + "/" + group + "/" + date_path + "/" + options.access_token).then(function(response) {
            if (!response.ok) {
                //console.error("Server " + process.argv[5 + 2 * i] + " (" + process.argv[6 + 2 * i] + ")" + " response status: " + response.status + ". Try later");
                console.error("Server " + Indices[i] + " (" + Addresses[i] + ")" + " response status: " + response.status + ". Try later.");
                process.exit(1);

            } else {
                response.text().then(function(text) {
                    //console.log("Value received by server " + process.argv[5 + 2 * i] + " (" + process.argv[6 + 2 * i] + "): " + text);
                    console.log("Value received by server " + Indices[i] + " (" + Addresses[i] + "): " + text);
                    if (!email) email = text.split('..')[2];
                    else if (text.split('..')[2] != email) throw ("Inconsistent values received from different servers");
                    if (!month) {
                        month = text.split('..')[3];
                    } else if (text.split('..')[3] != month) throw ("Inconsistent values received from different servers");
                    if (!year) year = text.split('..')[4];
                    else if (text.split('..')[4] != year) throw ("Inconsistent values received from different servers");
                    if (!Provider) Provider = text.split('..')[1];
                    else if (text.split('..')[1] != Provider) throw ("Inconsistent values received by different servers");

                    pk[Q[i]] = bls.bls12_381.G2.ProjectivePoint.fromHex(text.split('..')[5]);
                    hash[Q[i]] = bls.bls12_381.G1.ProjectivePoint.fromHex(text.split('..')[6]);
                    t--;
                    if (t == 0) Finalize();
                }).catch(function(err) {
                    console.error(err);
                });
            }

        });

    }

} catch (err) {

    console.error(err);
    process.exit(1);
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
    if (Provider != provider) {
        console.error("Received token shares are for provider " + Provider + " but you requested a token for provider " + provider);
        process.exit(1);
    }
    ComputeLagrangeCoefficients(lambda, options.threshold, Q);
    var tmp = bls.bls12_381.G2.ProjectivePoint.BASE.subtract(bls.bls12_381.G2.ProjectivePoint.BASE);
    var tmp2 = bls.bls12_381.G1.ProjectivePoint.BASE.subtract(bls.bls12_381.G1.ProjectivePoint.BASE);
    for (let i = 0n; i < options.threshold; i++) {
        pk[Q[i]] = pk[Q[i]].multiply(lambda[Q[i]]);
        hash[Q[i]] = hash[Q[i]].multiply(lambda[Q[i]]);
        tmp = tmp.add(pk[Q[i]]);
        tmp2 = tmp2.add(hash[Q[i]]);
    }
    var mpk = tmp;
    var token = tmp2;
    console.log("reconstructed master public key: " + mpk.toHex());
    const msg = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year);
    const h = bls.bls12_381.G1.hashToCurve(msg);
    const t1 = bls.bls12_381.pairing(h, mpk);
    const t2 = bls.bls12_381.pairing(token, bls.bls12_381.G2.ProjectivePoint.BASE);
    if (bls.bls12_381.fields.Fp12.eql(t1, t2) == false) {
        console.error("Verification of reconstructed token: failure.");
        process.exit(1);
    }
    console.log("reconstructed token: " + token.toHex());
    console.log("Verification of reconstructed token: success.");
}
