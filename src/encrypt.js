// usage:
// node encrypt.js -k mpk -e email (or domain/phone) -m month.year  [OPTIONS]
// the message is taken from the stdin

const bls = require('@noble/curves/bls12-381');
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const bls_verify = require("@noble/curves/abstract/bls");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const loi_utils = require("./utils");
const commander = require('commander');
const crypto = require('crypto');
const {
    Console
} = require('console');
const fs = require('fs');
commander
    .version('1.0.0', '-v, --version')
    .usage('-k <value> -e <value> -m <value> [OPTIONS]')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email. This value may be a domain when used in combination with tokens obtained by get_token.js with the -g option or may be a phone number for \"google.phone\" provider.')
    .requiredOption('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\"). Default is \"google\".')
    .option('-oc, --output_ciphertext <value>', 'write the ciphertext to the file <value> instead of writing it to the stdout.')
    .option('-f, --friends <value>', 'grant the token only to users with <value> total counts of friends.')
    .option('-cca2, --cca2', 'encrypt with security against adaptive chosen ciphertext attacks. This is the strongest form of security.')
    .parse(process.argv);

try {
    const options = commander.opts();
    var provider;
    provider = loi_utils.handleProviders(options, provider);
    const month = options.month.split('.')[0];
    const year = options.month.split('.')[1];
    const mpk = bls.bls12_381.G2.ProjectivePoint.fromHex(options.key);
    const email = options.email;
    var Log;
    Log = new Console({
        stdout: options.output_ciphertext ? fs.createWriteStream(options.output_ciphertext) : process.stdout,
        stderr: process.stderr,
    });
    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);

    if (!options.cca2) {
        const randtmp = bls.bls12_381.utils.randomPrivateKey();
        const derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', 48); // 48 bytes for 32-byte randomness
        const fp = mod.Field(bls.bls12_381.params.r);
        const s = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
        const A = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(s);
        const mpk_to_s = mpk.multiply(s);

        const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends);
        const h = bls.bls12_381.G1.hashToCurve(id);
        const g_id = bls.bls12_381.pairing(h, mpk_to_s);
        var B = bls.bls12_381.fields.Fp12.toBytes(g_id);

        loi_utils.read(process.stdin).then(function(msg) {
            msg = hashes.utf8ToBytes(msg);
            const length = msg.length;
            const B_expanded = hkdf.hkdf(sha256.sha256, B, undefined, 'application', length);
            msg = hashes.bytesToHex(msg);
            B = loi_utils.xor(hashes.bytesToHex(B_expanded), msg);
            const ciphertext = length + "." + A.toHex() + "." + B;
            if (!options.output_ciphertext) console.log("ciphertext: " + ciphertext);
            else {
                console.log("DEBUG: ciphertext written to file " + options.output_ciphertext);
                Log.log(ciphertext);
            }
        });
    } else {
        loi_utils.read(process.stdin).then(function(msg) {
            msg = hashes.utf8ToBytes(msg);
            const sigma = crypto.randomBytes(msg.length);
            const sigma_msg = new Uint8Array(sigma.length + msg.length);
            sigma_msg.set(sigma);
            sigma_msg.set(msg, sigma.length);
            const derived = hkdf.hkdf(sha256.sha256, sigma_msg, undefined, 'application', 48); // 48 bytes for 32-byte randomness
            const fp = mod.Field(bls.bls12_381.params.r);
            const s = fp.create(mod.hashToPrivateScalar(derived, bls.bls12_381.params.r));
            const A = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(s);
            const mpk_to_s = mpk.multiply(s);
            const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends);
            const h = bls.bls12_381.G1.hashToCurve(id);
            const g_id = bls.bls12_381.pairing(h, mpk_to_s);
            var B = bls.bls12_381.fields.Fp12.toBytes(g_id);
            const length = msg.length;
            const B_expanded = hkdf.hkdf(sha256.sha256, B, undefined, 'application', length);
            msg = hashes.bytesToHex(msg);
            B = loi_utils.xor(hashes.bytesToHex(B_expanded), hashes.bytesToHex(sigma));
            const sigma_expanded = hkdf.hkdf(sha256.sha256, sigma, undefined, 'application', sigma.length);
            const C = loi_utils.xor(hashes.bytesToHex(sigma_expanded), msg);
            if (!options.output_ciphertext) console.log("ciphertext: " + ciphertext);
            const ciphertext = length + "." + A.toHex() + "." + B + "." + C;
            if (!options.output_ciphertext) console.log("ciphertext: " + ciphertext);
            else {
                console.log("DEBUG: ciphertext written to file " + options.output_ciphertext);
                Log.log(ciphertext);
            }


        });
    }

} catch (err) {
    console.error("Encryption error: " + err.message);
    process.exit(1);
}