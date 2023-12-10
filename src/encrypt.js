// usage:
// node encrypt.js -k mpk -e email (or domain) -m month.year 
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

commander
    .version('1.0.0', '-v, --version')
    .usage('-k <value> -e <value> -m <value>')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email or domain.')
    .requiredOption('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (currently only \"google\" is supported).')
    .parse(process.argv);

const options = commander.opts();
var provider;
if (options.provider && options.provider !== "google") {
    console.error("Supported providers: google.");
    process.exit(1);
} else provider = "google";

const month = options.month.split('.')[0];
const year = options.month.split('.')[1];
const mpk = bls.bls12_381.G2.ProjectivePoint.fromHex(options.key);
const email = options.email;


const randtmp = bls.bls12_381.utils.randomPrivateKey();
const derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', 48); // 48 bytes for 32-byte randtmp
const fp = mod.Field(bls.bls12_381.params.r);
const s = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
const A = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(s);
const mpk_to_s = mpk.multiply(s);

const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year);
const h = bls.bls12_381.G1.hashToCurve(id);
const g_id = bls.bls12_381.pairing(h, mpk_to_s);
var B = bls.bls12_381.fields.Fp12.toBytes(g_id);

read(process.stdin).then(function(msg) {
    msg = hashes.utf8ToBytes(msg);
    var length = msg.length;
    const B_expanded = hkdf.hkdf(sha256.sha256, B, undefined, 'application', length);
    msg = hashes.bytesToHex(msg);
    B = xor(hashes.bytesToHex(B_expanded), msg);
    console.log("ciphertext: " + length + "." + A.toHex() + "." + B);
});

function xor(hex1, hex2) {
    const buf1 = Buffer.from(hex1, 'hex');
    const buf2 = Buffer.from(hex2, 'hex');
    const bufResult = buf1.map((b, i) => b ^ buf2[i]);
    return bufResult.toString('hex');
}
async function read(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}