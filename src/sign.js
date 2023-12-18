// usage:
// node sign.js -T token -k mpk -e email (or domain/phone) -m month.year [OPTIONS]
// the message is taken from the stdin

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
    .usage('-T <value> -k <value> -e <value> -m <value> [OPTIONS]')
    .requiredOption('-T, --token <value>', 'the token.')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email. This value may also be a domain when used in combination with tokens obtained by get_token.js with the -g option or may also be a phone number for \"google.phone\" provider.')
    .requiredOption('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\"). Default is \"google\".')
    .option('-os, --output_signature <value>', 'write the signature to the file <value> instead of writing it to the stdout.')
    .option('-f, --friends <value>', 'gran the token only to users with <value> total counts of friends.')
    .parse(process.argv);

const options = commander.opts();
var provider;
provider = loi_utils.handleProviders(options, provider);
var Log;
try {
    Log = new Console({
        stdout: options.output_signature ? fs.createWriteStream(options.output_signature) : process.stdout,
        stderr: process.stderr,
    });
} catch (err) {
    console.error(err);
    process.exit(1);
}
const fetch_opts = loi_utils.handleOptions(options, provider);

const month = options.month.split('.')[0];
const year = options.month.split('.')[1];
const mpk = bls.bls12_381.G2.ProjectivePoint.fromHex(options.key);
const token = bls.bls12_381.G1.ProjectivePoint.fromHex(options.token);
const email = options.email;



loi_utils.read(process.stdin).then(function(msg) {
    var randtmp = bls.bls12_381.utils.randomPrivateKey();
    var derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', 48); // 48 bytes for 32-byte randtmp
    const fp = mod.Field(bls.bls12_381.params.r);
    const r = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
    const C = mpk.multiply(r);
    const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_opts);
    const h = bls.bls12_381.G1.hashToCurve(id);
    const E = bls.bls12_381.G1.ProjectivePoint.BASE.multiply(r);
    const F = token.multiply(r);
    randtmp = bls.bls12_381.utils.randomPrivateKey();
    const a = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
    const pi_A = bls.bls12_381.G1.ProjectivePoint.BASE.multiply(a);
    const input = hashes.utf8ToBytes(E.toHex() + "." + pi_A.toHex() + "." + msg); // we hash input = statement E + first message pi_A + message msg
    derived = hkdf.hkdf(sha256.sha256, input, undefined, 'application', 48);
    const e = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r)); // e is the hash of input converted to scalar
    const pi_z = fp.add(a, fp.mul(e, r)); // pi_z = a + e*r
    const signature = C.toHex() + "." + E.toHex() + "." + F.toHex() + "." + pi_A.toHex() + "." + utils.numberToHexUnpadded(pi_z);
    if (!options.output_signature) console.log("signature: " + signature);
    else {

        console.log("DEBUG: signature written to file " + options.output_signature);
        Log.log(signature);
    }
});