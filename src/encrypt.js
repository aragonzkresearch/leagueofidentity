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
const mcl_bases = require('./mcl_bases');
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
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\", \"eth\", \"nintendo\"). Default is \"google\".')
    .option('-oc, --output_ciphertext <value>', 'write the ciphertext to the file <value> instead of writing it to the stdout.')
    .option('-f, --friends <value>', 'For \"facebook\" provider grant the token only to a user with at least <value> total counts of friends. For \"eth\" provider grant the token only to an Ethereum address with at least <value> of Wei held by the address.')
    .option('-anon, --anonymous', 'for tokens granted through the \'--anonymous\' option.')
    .option('-cca2, --cca2', 'encrypt with security against adaptive chosen ciphertext attacks. This is the strongest form of security.')
    .option('-cc, --cross_country', 'For digital identity cards (DICs) only: if this option is set the provider info used to perform cryptographic operations will be shortned to \'dic\' rather than e.g., \'dic.it\'. In this way, a token for e.g. a Spanish DIC and an Italian DIC will correspond to the same provider (i.e., \'dic\'). Even if this option is used you must anyway specify the full provider (e.g., \'dic.it\') in order to perform operations that are country specific.')
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine.')
    .option('-t, --tinyurl', 'Use tinyurl.com service to compress the ciphertext to a short string.')
    .option('-h, --hex', 'Output the ciphertext as hexadecimal string. Useful in combination with \'-t\' to output the path of the tinyurl site to use in Ethereum DApps. Use it only in combination with the option \'-t\'.')
    .parse(process.argv);

try {
    var API_TINY, API_PATH, API_URL;
    const options = commander.opts();
    var provider;
    provider = loi_utils.handleProviders(options, provider);
    const month = loi_utils.getMonth(options);
    const year = loi_utils.getYear(options);
    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);
    const fetch_ethereum = options.ethereum ? "1" : "null";


    //const month = options.month.split('.')[0];
    //const year = options.month.split('.')[1];
    const email = options.email;
    var Log;
    Log = new Console({
        stdout: options.output_ciphertext ? fs.createWriteStream(options.output_ciphertext) : process.stdout,
        stderr: process.stderr,
    });
    // for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
    if (options.cross_country) provider = provider.split('.')[0];

    var bg, mcl, FrTmp, G2Base;
    if (fetch_ethereum === "null") {
        bg = require('@noble/curves/bls12-381').bls12_381;
        main();
    } else {
        bg = require('@noble/curves/bn254').bn254;
        mcl = require('mcl-wasm');
        mcl.init(mcl.BN_SNARK1).then(() => {
            G2Base = mcl_bases.G2Base();
            main();
        }).catch((err) => {
            console.error(err.message);
            process.exit(1);
        });
    }


    async function getTinyURL(CT) {
        var request = API_TINY + API_URL + CT;

        return fetch(request).then(function(response) {
            return response.text();
        });
    }

    function Finalize(options, ciphertext, Log) {

        if (!options.output_ciphertext) console.log("ciphertext: " + ciphertext);
        else {
            if (options.tinyurl) {

                getTinyURL(ciphertext).then(function(text) {
                    console.log("DEBUG: ciphertext written to file " + options.output_ciphertext);
                    text = new URL(text).pathname.substr(API_PATH.length);
                    if (options.hex) text = utils.bytesToHex(hashes.utf8ToBytes(text));
                    Log.log(text);
                }).catch((err) => {
                    console.error("tinyurl.com service not working. Try later" + err.message);
                    process.exit(1);
                });
            } else {
                console.log("DEBUG: ciphertext written to file " + options.output_ciphertext);
                Log.log(ciphertext);
            }
        }

    }

    async function main() {
        const JsonContent = await loi_utils.read(fs.createReadStream("./params.json"));
        const data = JSON.parse(JsonContent);
        API_TINY = data.params.API_TINY;
        API_PATH = data.params.API_PATH;
        API_URL = data.params.API_URL + API_PATH; // Just as example. Change it in real implementations.
        var ciphertext;
        const fp = mod.Field(fetch_ethereum === 'null' ? bg.params.r : bg.CURVE.n);
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.G2();
            FrTmp.setStr(options.key, 16);
        }
        const mpk = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.fromHex(options.key) : FrTmp;
        if (!options.cca2) {
            const randtmp = bg.utils.randomPrivateKey();
            const derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32); // 48 bytes for 32-bytes input 


            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                //  FrTmp.setStr(utils.bytesToHex(derived), 16);
                FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
            }
            const s = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp;
            const A = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.BASE.multiply(s) : mcl.mul(G2Base, s);
            const mpk_to_s = fetch_ethereum === 'null' ? mpk.multiply(s) : mcl.mul(mpk, s);

            const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
            const h = eth.hashToCurve(id, fetch_ethereum, fetch_ethereum === 'null' ? bg : mcl);
            const g_id = (fetch_ethereum === 'null' ? bg : mcl).pairing(h, mpk_to_s);
            var B = fetch_ethereum === 'null' ? bg.fields.Fp12.toBytes(g_id) : g_id.getStr(16);
            loi_utils.read(process.stdin).then(function(msg) {
                msg = hashes.utf8ToBytes(msg);
                const length = msg.length;
                const B_expanded = hkdf.hkdf(sha256.sha256, B, undefined, 'application', length);
                msg = hashes.bytesToHex(msg);
                B = loi_utils.xor(hashes.bytesToHex(B_expanded), msg);
                ciphertext = length + "." + (fetch_ethereum === 'null' ? A.toHex() : A.getStr(16)) + "." + B;
                Finalize(options, ciphertext, Log);
            }).catch((err) => {
                console.error(err.message);
                process.exit(1);
            });
        } else {
            loi_utils.read(process.stdin).then(function(msg) {
                msg = hashes.utf8ToBytes(msg);
                const sigma = crypto.randomBytes(msg.length);
                const sigma_msg = new Uint8Array(sigma.length + msg.length);
                sigma_msg.set(sigma);
                sigma_msg.set(msg, sigma.length);
                const derived = hkdf.hkdf(sha256.sha256, sigma_msg, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32);
                if (fetch_ethereum !== 'null') {
                    FrTmp = new mcl.Fr();
                    //       FrTmp.setStr(utils.bytesToHex(derived), 16);
                    FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
                }
                const s = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp;
                const A = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.BASE.multiply(s) : mcl.mul(G2Base, s);
                const mpk_to_s = fetch_ethereum === 'null' ? mpk.multiply(s) : mcl.mul(mpk, s);
                const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
                //const h = bg.G1.hashToCurve(id);
                const h = eth.hashToCurve(id, fetch_ethereum, fetch_ethereum === 'null' ? bg : mcl);
                const g_id = (fetch_ethereum === 'null' ? bg : mcl).pairing(h, mpk_to_s);
                var B = fetch_ethereum === 'null' ? bg.fields.Fp12.toBytes(g_id) : g_id.getStr(16);
                const length = msg.length;
                const B_expanded = hkdf.hkdf(sha256.sha256, B, undefined, 'application', length);
                msg = hashes.bytesToHex(msg);
                B = loi_utils.xor(hashes.bytesToHex(B_expanded), hashes.bytesToHex(sigma));
                const sigma_expanded = hkdf.hkdf(sha256.sha256, sigma, undefined, 'application', sigma.length);
                const C = loi_utils.xor(hashes.bytesToHex(sigma_expanded), msg);
                if (!options.output_ciphertext) console.log("ciphertext: " + ciphertext);
                ciphertext = length + "." + (fetch_ethereum === 'null' ? A.toHex() : A.getStr(16)) + "." + B + "." + C;
                Finalize(options, ciphertext, Log);
                /*if (!options.output_ciphertext) console.log("ciphertext: " + ciphertext);
                else {
                    console.log("DEBUG: ciphertext written to file " + options.output_ciphertext);
                    Log.log(ciphertext);
                }
*/

            }).catch((err) => {
                console.error(err.message);
                process.exit(1);
            });
        }
    }

} catch (err) {
    console.error("Encryption error: " + err.message);
    process.exit(1);
}