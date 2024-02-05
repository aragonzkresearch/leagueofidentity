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
const mcl_bases = require("./mcl_bases");
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
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine.')
    .option('-t, --tinyurl', 'Use tinyurl.com service to compress the ciphertext to a short string.')
    .option('-h, --hex', 'Interpret the ciphertext as hexadecimal string and convert it to binary before using it for decryption. Useful in combination with \'-t\'. Use it only in combination with the option \'-t\'.')
    .parse(process.argv);

    var TINY_URL, API_PATH;
async function getLongURL(CT) {
    var request = TINY_URL + CT;
    return fetch(request).then(function(response) {
        return response.url;
    }).catch(function(err) {

        console.error("Unable to decrypt. The problem can be due to an invalid ciphertext or the tinyurl.com service not working. Try later");
        process.exit(1);
    });
}
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

    async function main() {
        try {
        const JsonContent = await loi_utils.read(fs.createReadStream("./params.json"));
        const data = JSON.parse(JsonContent);
        TINY_URL = data.params.TINY_URL;
        API_PATH = data.params.API_PATH;
            const fp = mod.Field(fetch_ethereum === 'null' ? bg.params.r : bg.CURVE.n);
            const month = loi_utils.getMonth(options);
            const year = loi_utils.getYear(options);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.G2();
                FrTmp.setStr(options.key, 16);
            }
            const mpk = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.fromHex(options.key) : FrTmp;
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.G1();
                FrTmp.setStr(options.token, 16);
            }
            const token = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.fromHex(options.token) : FrTmp;
            const email = options.email;
            var ciphertext = options.ciphertext;
            if (options.hex) ciphertext = new TextDecoder().decode(utils.hexToBytes(ciphertext));
            if (options.tinyurl) {
                ciphertext = await getLongURL(ciphertext);
                ciphertext = decodeURI(new URL(ciphertext).pathname.substr(API_PATH.length)); 

            }

            // for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
            if (options.cross_country) provider = provider.split('.')[0];
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.G2();
                FrTmp.setStr(ciphertext.split('.')[1], 16);
            }
            if (!options.cca2) {
                const A = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.fromHex(ciphertext.split('.')[1]) : FrTmp;
                const B = ciphertext.split('.')[2];
                const length = parseInt(ciphertext.split('.')[0]);


                const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
                const h = eth.hashToCurve(id, fetch_ethereum, fetch_ethereum === 'null' ? bg : mcl);
                const t1 = (fetch_ethereum === 'null' ? bg : mcl).pairing(h, mpk);
                const t2 = fetch_ethereum === 'null' ? bg.pairing(token, bg.G2.ProjectivePoint.BASE) : mcl.pairing(token, G2Base);
                if (fetch_ethereum === 'null' ? (bg.fields.Fp12.eql(t1, t2) == false) : !t1.isEqual(t2)) {
                    console.error("Verification of token: failure.");
                    process.exit(1);
                }
                console.log("DEBUG: Verification of token: success.");
                const g_id = (fetch_ethereum === 'null' ? bg : mcl).pairing(token, A);
                var B_computed = fetch_ethereum === 'null' ? bg.fields.Fp12.toBytes(g_id) : g_id.getStr(16);

                const B_expanded = hkdf.hkdf(sha256.sha256, B_computed, undefined, 'application', length);
                B_computed = hashes.bytesToHex(B_expanded);
                var decoder = new TextDecoder();
                if (!options.output_msg) console.log("decrypted message: " + decoder.decode(utils.hexToBytes(loi_utils.xor(B_computed, B))));
                else {

                    console.log("DEBUG: decrypted message written to file " + options.output_msg);
                    Log.log(decoder.decode(utils.hexToBytes(loi_utils.xor(B_computed, B))));
                }

            } else {
                const A = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.fromHex(ciphertext.split('.')[1]) : FrTmp;
                const B = ciphertext.split('.')[2];
                const length = parseInt(ciphertext.split('.')[0]);
                const C = ciphertext.split('.')[3];


                const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
                const h = eth.hashToCurve(id, fetch_ethereum, fetch_ethereum === 'null' ? bg : mcl);
                const t1 = (fetch_ethereum === 'null' ? bg : mcl).pairing(h, mpk);
                const t2 = fetch_ethereum === 'null' ? bg.pairing(token, bg.G2.ProjectivePoint.BASE) : mcl.pairing(token, G2Base);
                if (fetch_ethereum === 'null' ? (bg.fields.Fp12.eql(t1, t2) == false) : !t1.isEqual(t2)) {
                    console.error("Verification of token: failure.");
                    process.exit(1);
                }
                console.log("DEBUG: Verification of token: success.");
                const g_id = (fetch_ethereum === 'null' ? bg : mcl).pairing(token, A);
                var B_computed = fetch_ethereum === 'null' ? bg.fields.Fp12.toBytes(g_id) : g_id.getStr(16);
                const B_expanded = hkdf.hkdf(sha256.sha256, B_computed, undefined, 'application', length);
                B_computed = hashes.bytesToHex(B_expanded);
                const sigma = utils.hexToBytes(loi_utils.xor(B_computed, B));
                const sigma_expanded = hkdf.hkdf(sha256.sha256, sigma, undefined, 'application', sigma.length);
                const msg = utils.hexToBytes(loi_utils.xor(hashes.bytesToHex(sigma_expanded), C));
                const sigma_msg = new Uint8Array(sigma.length + msg.length);
                sigma_msg.set(sigma);
                sigma_msg.set(msg, sigma.length);
                const derived = hkdf.hkdf(sha256.sha256, sigma_msg, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32); // 48 bytes for 32-bytes input 

                if (fetch_ethereum !== 'null') {
                    FrTmp = new mcl.Fr();
                    //    FrTmp.setStr(utils.bytesToHex(derived), 16);
                    FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
                }
                const s = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp;
                const A_computed = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.BASE.multiply(s) : mcl.mul(G2Base, s);
                var success_flag;

                if (fetch_ethereum === 'null')
                    success_flag = A_computed.equals(A) ? "1" : "0";

                else success_flag = A_computed.getStr(16) === A.getStr(16) ? "1" : "0";
                var decoder = new TextDecoder();
                if (!options.output_msg) console.log("decrypted flag+message: " + success_flag + decoder.decode(msg));
                else {

                    console.log("DEBUG: decrypted flag+message written to file " + options.output_msg);
                    Log.log(success_flag + decoder.decode(msg));
                }



            }
        } catch (err) {

            console.error("Decryption error");
            process.exit(1);
        }
    }
} catch (err) {

    console.error("Decryption error");
    process.exit(1);
}
