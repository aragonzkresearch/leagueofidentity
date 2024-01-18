// usage:
// node decrypt.js -T token -k mpk -e email (or domain/phone) -m month.year -c ciphertext

const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const commander = require('commander');
const loi_utils = require("./utils");
const eth = require("./ethereum_mode");
const {
    Console
} = require('console');
const fs = require('fs');

commander
    .version('1.0.0', '-v, --version')
    .usage('-T <value> -k <value> -e <value> -m <value> -c <value> [OPTIONS]')
    .requiredOption('-T, --token <value>', 'the token.')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email. This value may also be a domain when used in combination with tokens obtained by get_token.js with the -g option or may also be a phone number for \"google.phone\" provider.')
    .requiredOption('-c, --ciphertext <value>', 'the ciphertext.')
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\", \"eth\", \"nintendo\"). Default is \"google\".')
    .option('-f, --friends <value>', 'For \"facebook\" provider grant the token only to a user with at least <value> total counts of friends. For \"eth\" provider grant the token only to an Ethereum address with at least <value> of Wei held by the address.')
    .option('-om, --output_msg <value>', 'write the decrypted message to the file <value> instead of writing it to the stdout.')
    .option('-anon, --anonymous', 'for tokens granted through the \'--anonymous\' option.')
    .option('-cca2, --cca2', 'decrypt with security against adaptive chosen ciphertext attacks. This is the strongest form of security. The first byte of the decrypted message will be 0/1 to denote failure or success of decryption.')
    .option('-cc, --cross_country', 'For digital identity cards (DICs) only: if this option is set the provider info used to perform cryptographic operations will be shortned to \'dic\' rather than e.g., \'dic.it\'. In this way, a token for e.g. a Spanish DIC and an Italian DIC will correspond to the same provider (i.e., \'dic\'). Even if this option is used you must anyway specify the full provider (e.g., \'dic.it\') in order to perform operations that are country specific.')
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine. NOT SUPPORTED YET, DO NOT USE IT.')
    .parse(process.argv);

try {
    const options = commander.opts();
    var provider;
    provider = loi_utils.handleProviders(options, provider);
    var Log;
    Log = new Console({
        stdout: options.output_msg ? fs.createWriteStream(options.output_msg) : process.stdout,
        stderr: process.stderr,
    });

    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);
    const fetch_ethereum = options.ethereum ? "1" : "null";
    var bg;
    if (fetch_ethereum === "null") bg = require('@noble/curves/bls12-381').bls12_381;
    else bg = require('@noble/curves/bn254').bn254;
    const month = loi_utils.getMonth(options);
    const year = loi_utils.getYear(options);
    //const month = options.month.split('.')[0];
    //const year = options.month.split('.')[1];
    const token = bg.G1.ProjectivePoint.fromHex(options.token);
    const mpk = bg.G2.ProjectivePoint.fromHex(options.key);
    const email = options.email;
    const ciphertext = options.ciphertext;
    // for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
    if (options.cross_country) provider = provider.split('.')[0];
    if (!options.cca2) {
        const A = bg.G2.ProjectivePoint.fromHex(ciphertext.split('.')[1]);
        const B = ciphertext.split('.')[2];
        const length = parseInt(ciphertext.split('.')[0]);


        const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
        //const h = bg.G1.hashToCurve(id);
        const h = eth.hashToCurve(id, fetch_ethereum);
        const t1 = bg.pairing(h, mpk);
        const t2 = bg.pairing(token, bg.G2.ProjectivePoint.BASE);
        if (bg.fields.Fp12.eql(t1, t2) == false) {
            console.error("Verification of token: failure.");
            process.exit(1);
        }
        console.log("DEBUG: Verification of token: success.");
        const g_id = bg.pairing(token, A);
        var B_computed = bg.fields.Fp12.toBytes(g_id);

        const B_expanded = hkdf.hkdf(sha256.sha256, B_computed, undefined, 'application', length);
        B_computed = hashes.bytesToHex(B_expanded);
        var decoder = new TextDecoder();
        if (!options.output_msg) console.log("decrypted message: " + decoder.decode(utils.hexToBytes(loi_utils.xor(B_computed, B))));
        else {

            console.log("DEBUG: decrypted message written to file " + options.output_msg);
            Log.log(decoder.decode(utils.hexToBytes(loi_utils.xor(B_computed, B))));
        }

    } else {
        const A = bg.G2.ProjectivePoint.fromHex(ciphertext.split('.')[1]);
        const B = ciphertext.split('.')[2];
        const length = parseInt(ciphertext.split('.')[0]);
        const C = ciphertext.split('.')[3];


        const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
        //const h = bg.G1.hashToCurve(id);
        const h = eth.hashToCurve(id, fetch_ethereum);
        const t1 = bg.pairing(h, mpk);
        const t2 = bg.pairing(token, bg.G2.ProjectivePoint.BASE);
        if (bg.fields.Fp12.eql(t1, t2) == false) {
            console.error("Verification of token: failure.");
            process.exit(1);
        }
        console.log("DEBUG: Verification of token: success.");
        const g_id = bg.pairing(token, A);
        var B_computed = bg.fields.Fp12.toBytes(g_id);
        const B_expanded = hkdf.hkdf(sha256.sha256, B_computed, undefined, 'application', length);
        B_computed = hashes.bytesToHex(B_expanded);
        const sigma = utils.hexToBytes(loi_utils.xor(B_computed, B));
        const sigma_expanded = hkdf.hkdf(sha256.sha256, sigma, undefined, 'application', sigma.length);
        const msg = utils.hexToBytes(loi_utils.xor(hashes.bytesToHex(sigma_expanded), C));
        const sigma_msg = new Uint8Array(sigma.length + msg.length);
        sigma_msg.set(sigma);
        sigma_msg.set(msg, sigma.length);
        const derived = hkdf.hkdf(sha256.sha256, sigma_msg, undefined, 'application', 48); // 48 bytes for 32-byte randomness
        const fp = mod.Field(bg.params.r);
        const s = fp.create(mod.hashToPrivateScalar(derived, bg.params.r));
        const A_computed = bg.G2.ProjectivePoint.BASE.multiply(s);
        const success_flag = A_computed.equals(A) ? "1" : "0";
        var decoder = new TextDecoder();
        if (!options.output_msg) console.log("decrypted flag+message: " + success_flag + decoder.decode(msg));
        else {

            console.log("DEBUG: decrypted flag+message written to file " + options.output_msg);
            Log.log(success_flag + decoder.decode(msg));
        }



    }

} catch (err) {

    console.error("Decryption error: " + err.message);
    process.exit(1);
}
