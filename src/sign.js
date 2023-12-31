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
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\"). Default is \"google\".')
    .option('-os, --output_signature <value>', 'write the signature to the file <value> instead of writing it to the stdout.')
    .option('-anon, --anonymous', 'for tokens granted through the \'--anonymous\' option.')
    .option('-f, --friends <value>', 'for tokens granted only to users with at least <value> total counts of friends.')
    .option('-cc, --cross_country', 'For digital identity cards (DICs) only: if this option is set the provider info used to perform cryptographic operations will be shortned to \'dic\' rather than e.g., \'dic.it\'. In this way, a token for e.g. a Spanish DIC and an Italian DIC will correspond to the same provider (i.e., \'dic\'). Even if this option is used you must anyway specify the full provider (e.g., \'dic.it\') in order to perform operations that are country specific.')
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
const fetch_friends = loi_utils.handleOptionFriends(options, provider);
const fetch_anon = loi_utils.handleOptionAnon(options, provider);

const month = loi_utils.getMonth(options);
const year = loi_utils.getYear(options);
//const month = options.month.split('.')[0];
//const year = options.month.split('.')[1];
const mpk = bls.bls12_381.G2.ProjectivePoint.fromHex(options.key);
const token = bls.bls12_381.G1.ProjectivePoint.fromHex(options.token);
const email = options.email; // TODO: we could reject if the email in the token is different from the one provided as input to the command.
// for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
if (options.cross_country) provider = provider.split('.')[0];


loi_utils.read(process.stdin).then(function(msg) {
    var randtmp = bls.bls12_381.utils.randomPrivateKey();
    var derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', 48); // 48 bytes for 32-byte randomness
    const fp = mod.Field(bls.bls12_381.params.r);
    const r = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
    const C = mpk.multiply(r);
    const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + fetch_anon);
    const h = bls.bls12_381.G1.hashToCurve(id);
    const E = bls.bls12_381.G1.ProjectivePoint.BASE.multiply(r);
    const F = token.multiply(r);
    randtmp = bls.bls12_381.utils.randomPrivateKey();
    derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', 48); // 48 bytes for 32-byte randomness
    const a = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
    const pi_A = bls.bls12_381.G1.ProjectivePoint.BASE.multiply(a);
    const input = hashes.utf8ToBytes(E.toHex() + "." + pi_A.toHex() + "." + msg + "." + email); // we hash input = statement E + first message pi_A + message msg + email
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
