// usage:
// node encrypt.js -k mpk -e email (or domain/phone) -m month.year  [OPTIONS]
// the message is taken from the stdin

const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const loi_utils = require("./utils");
const eth = require("./ethereum_mode");
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
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\"). Default is \"google\".')
    .option('-oc, --output_ciphertext <value>', 'write the ciphertext to the file <value> instead of writing it to the stdout.')
    .option('-f, --friends <value>', 'for tokens granted only to users with at least <value> total counts of friends.')
    .option('-anon, --anonymous', 'for tokens granted through the \'--anonymous\' option.')
    .option('-cca2, --cca2', 'encrypt with security against adaptive chosen ciphertext attacks. This is the strongest form of security.')
    .option('-cc, --cross_country', 'For digital identity cards (DICs) only: if this option is set the provider info used to perform cryptographic operations will be shortned to \'dic\' rather than e.g., \'dic.it\'. In this way, a token for e.g. a Spanish DIC and an Italian DIC will correspond to the same provider (i.e., \'dic\'). Even if this option is used you must anyway specify the full provider (e.g., \'dic.it\') in order to perform operations that are country specific.')
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine. NOT SUPPORTED YET, DO NOT USE IT.')
    .parse(process.argv);

try {
    const options = commander.opts();
    var provider;
    provider = loi_utils.handleProviders(options, provider);
    const month = loi_utils.getMonth(options);
    const year = loi_utils.getYear(options);
    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);
    const fetch_ethereum = options.ethereum ? "1" : "null";
    var bg;
    if (fetch_ethereum === "null") bg = require('@noble/curves/bls12-381').bls12_381;
    else bg = require('@noble/curves/bn254').bn254;
    //const month = options.month.split('.')[0];
    //const year = options.month.split('.')[1];
    const mpk = bg.G2.ProjectivePoint.fromHex(options.key);
    const email = options.email;
    var Log;
    Log = new Console({
        stdout: options.output_ciphertext ? fs.createWriteStream(options.output_ciphertext) : process.stdout,
        stderr: process.stderr,
    });
    // for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
    if (options.cross_country) provider = provider.split('.')[0];
    if (!options.cca2) {
        const randtmp = bg.utils.randomPrivateKey();
        const derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', 48); // 48 bytes for 32-byte randomness
        const fp = mod.Field(bg.params.r);
        const s = fp.create(mod.hashToPrivateScalar(derived, bg.params.r));
        const A = bg.G2.ProjectivePoint.BASE.multiply(s);
        const mpk_to_s = mpk.multiply(s);

        const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
        //const h = bg.G1.hashToCurve(id);
        const h = eth.hashToCurve(id, fetch_ethereum);
        const g_id = bg.pairing(h, mpk_to_s);
        var B = bg.fields.Fp12.toBytes(g_id);

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
            const fp = mod.Field(bg.params.r);
            const s = fp.create(mod.hashToPrivateScalar(derived, bg.params.r));
            const A = bg.G2.ProjectivePoint.BASE.multiply(s);
            const mpk_to_s = mpk.multiply(s);
            const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
            //const h = bg.G1.hashToCurve(id);
            const h = eth.hashToCurve(id, fetch_ethereum);
            const g_id = bg.pairing(h, mpk_to_s);
            var B = bg.fields.Fp12.toBytes(g_id);
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