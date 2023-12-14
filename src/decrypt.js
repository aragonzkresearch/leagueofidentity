// usage:
// node decrypt.js -T token -k mpk -e email (or domain) -m month.year -c ciphertext

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
    .usage('-T <value> -k <value> -e <value> -m <value> -c <value> [OPTIONS]')
    .requiredOption('-T, --token <value>', 'the token.')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email. This value may also be a domain when used in combination with tokens obtained by get_token.js with the -g option or may also be a phone number for \"google.phone\" provider.')
    .requiredOption('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .requiredOption('-c, --ciphertext <value>', 'the ciphertext.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\"). Default is \"google\".')
    .parse(process.argv);

const options = commander.opts();
var provider;
if (options.provider && options.provider !== "google" && options.provider !== "facebook" && options.provider !== "google.phone") {
    console.error("Supported providers: google, facebook, google.phone.");
    process.exit(1);
} else if (!options.provider) provider = "google";
else provider = options.provider;

const month = options.month.split('.')[0];
const year = options.month.split('.')[1];
const token = bls.bls12_381.G1.ProjectivePoint.fromHex(options.token);
const mpk = bls.bls12_381.G2.ProjectivePoint.fromHex(options.key);
const email = options.email;
const ciphertext = options.ciphertext;
const A = bls.bls12_381.G2.ProjectivePoint.fromHex(ciphertext.split('.')[1]);
const B = ciphertext.split('.')[2];
const length = parseInt(ciphertext.split('.')[0]);


const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year);
const h = bls.bls12_381.G1.hashToCurve(id);
const t1 = bls.bls12_381.pairing(h, mpk);
const t2 = bls.bls12_381.pairing(token, bls.bls12_381.G2.ProjectivePoint.BASE);
if (bls.bls12_381.fields.Fp12.eql(t1, t2) == false) {
    console.log("Verification of token: failure.");
    return;
}
console.log("Verification of token: success.");
const g_id = bls.bls12_381.pairing(token, A);
var B_computed = bls.bls12_381.fields.Fp12.toBytes(g_id);

const B_expanded = hkdf.hkdf(sha256.sha256, B_computed, undefined, 'application', length);
B_computed = hashes.bytesToHex(B_expanded);
var decoder = new TextDecoder();
console.log(decoder.decode(utils.hexToBytes(xor(B_computed, B))));

function xor(hex1, hex2) {
    const buf1 = Buffer.from(hex1, 'hex');
    const buf2 = Buffer.from(hex2, 'hex');
    const bufResult = buf1.map((b, i) => b ^ buf2[i]);
    return bufResult.toString('hex');
}
