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
const loi_utils = require("./utils");
const {
    Console
} = require('console');
const fs = require('fs');

commander
    .version('1.0.0', '-v, --version')
    .usage('-A <value> -t <value> -n <value> -l list [OPTIONS]')
    .requiredOption('-A, --access_token <value>', 'access token.')
    .requiredOption('-t, --threshold <value>', 'threshold of nodes required to reconstruct the master secret key.')
    .requiredOption('-n, --no_nodes <value>', 'total number of nodes.')
    .requiredOption('-l, --list <value...>', 'list of t values of the form i_1 server_1:port_1 ... i_t server_t:port_t, where t is the given threshold specified by the -t argument and each index i_1, ..., i_t is an integer between 1 and n, where n is the value specified by the -n argument.')
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-g, --group', 'request a group token.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\"). Default is \"google\".')
    .option('-ok, --output_key <value>', 'write the master public key to the file <value> instead of writing it to stdout.')
    .option('-ot, --output_token <value>', 'write the token to the file <value> instead of writing it to stdout.')
    .option('-f, --friends <value>', 'grant the token only to users with <value> total counts of friends.')
    .option('-anon, --anonymous', 'Use the access token AT specified to the argument -A as identity in order to achieve anonymity. You will need to specify the argument \'-e AT\' to all other commands and \'-e AT@domain\' when the the access token is obtained by using this command with the option \'-anon\' in combination with \'-g\'.')
    .parse(process.argv);

const options = commander.opts();
var provider;
provider = loi_utils.handleProviders(options, provider);
if (options.list.length != options.threshold * 2) {
    commander.help({
        error: true
    });
    return;
}
var LogMPK, LogTok;
try {
    LogMPK = new Console({
        stdout: options.output_key ? fs.createWriteStream(options.output_key) : process.stdout,
        stderr: process.stderr,
    });
    LogTok = new Console({
        stdout: options.output_token ? fs.createWriteStream(options.output_token) : process.stdout,
        stderr: process.stderr,
    });
} catch (err) {
    console.error(err.message);
    process.exit(1);
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
if (group === "1" && provider === "google.phone") {
    console.error("Option -g is not compatible with provider \"google.phone\".");
    process.exit(1);

}
const Month = !options.month ? "now" : options.month; // Month is "now" or a string of the form month.year with month between 0 and 11 and year of the form XXXX
var flag = 1;
var email, Provider, month, year;
var pk = [];
var hash = [];
var Q = [];
var lambda = [];
var date_path;
if (Month !== "now") {
    date_path = Month;
    month = Month.split('.')[0];
    year = Month.split('.')[1];
} else date_path = "now";
var t = options.threshold;
if (provider !== "facebook" && options.friends) {
    console.error("Option --friends compatibile only with provider \"facebook\"");
    process.exit(1);
}
const fetch_friends = loi_utils.handleOptionFriends(options, provider);
const fetch_anon = loi_utils.handleOptionAnon(options, provider);
try {
    for (let i = 0; i < options.threshold; i++) {
        Q[i] = BigInt(Indices[i]);

        fetch(Addresses[i] + "/" + provider + "/" + group + "/" + date_path + "/" + options.access_token + "/" + fetch_friends + "/" + fetch_anon).then(function(response) {
            if (!response.ok) {
                console.error("Server " + Indices[i] + " (" + Addresses[i] + ")" + " response status: " + response.status + ". Try later.");
                process.exit(1);

            } else {
                response.text().then(function(text) {
                    console.log("DEBUG: Value received by server " + Indices[i] + " (" + Addresses[i] + "): " + text);
                    if (!email) email = Buffer.from(utils.hexToBytes(text.split('..')[2])).toString('utf8');
                    else if (Buffer.from(utils.hexToBytes(text.split('..')[2])).toString('utf8') != email) throw ("Inconsistent values received from different servers");
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
                    console.error(err.message);
                });
            }

        }).catch((err) => {
            console.error(err.message);
            process.exit(1);
        });

    }

} catch (err) {

    console.error(err.message);
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
    const mpk = tmp;
    const token = tmp2;
    if (!options.output_key) console.log("reconstructed master public key: " + mpk.toHex());
    else {

        console.log("DEBUG: master public key written to file " + options.output_key);
        LogMPK.log(mpk.toHex());
    }
    const id = "LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends;
    console.log(email);
    const msg = hashes.utf8ToBytes(id);
    const h = bls.bls12_381.G1.hashToCurve(msg);
    const t1 = bls.bls12_381.pairing(h, mpk);
    const t2 = bls.bls12_381.pairing(token, bls.bls12_381.G2.ProjectivePoint.BASE);
    if (bls.bls12_381.fields.Fp12.eql(t1, t2) == false) {
        console.error("Verification of reconstructed token: failure.");
        process.exit(1);
    }
    if (!options.output_token) console.log("reconstructed token: " + token.toHex() + " for identity " + id);
    else {
        console.log("DEBUG: token written to file " + options.output_token);
        LogTok.log(token.toHex());
    }
    console.log("DEBUG: Verification of reconstructed token: success.");
}