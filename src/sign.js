// usage:
// node sign.js -T token -k mpk -e email (or domain/phone) -m month.year [OPTIONS]
// the message is taken from the stdin

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
    .usage('-T <value> -k <value> -e <value> -m <value> [OPTIONS]')
    .requiredOption('-T, --token <value>', 'the token.')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email. This value may also be a domain when used in combination with tokens obtained by get_token.js with the -g option or may also be a phone number for \"google.phone\" provider.')
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\", \"eth\", \"nintendo\"). Default is \"google\".')
    .option('-os, --output_signature <value>', 'write the signature to the file <value> instead of writing it to the stdout.')
    .option('-anon, --anonymous', 'for tokens granted through the \'--anonymous\' option.')
    .option('-f, --friends <value>', 'For \"facebook\" provider grant the token only to a user with at least <value> total counts of friends. For \"eth\" provider grant the token only to an Ethereum address with at least <value> of Wei held by the address.')
    .option('-j, --json', 'Output the signature in JSON format.')
    .option('-h, --hex', 'Interpret the input message as hexadecimal string and convert it to binary before signing it.')
    .option('-cc, --cross_country', 'For digital identity cards (DICs) only: if this option is set the provider info used to perform cryptographic operations will be shortned to \'dic\' rather than e.g., \'dic.it\'. In this way, a token for e.g. a Spanish DIC and an Italian DIC will correspond to the same provider (i.e., \'dic\'). Even if this option is used you must anyway specify the full provider (e.g., \'dic.it\') in order to perform operations that are country specific.')
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine.')
    .parse(process.argv);

try {
    const options = commander.opts();
    var provider;
    provider = loi_utils.handleProviders(options, provider);
    var Log;
    Log = new Console({
        stdout: options.output_signature ? fs.createWriteStream(options.output_signature) : process.stdout,
        stderr: process.stderr,
    });
    const month = loi_utils.getMonth(options);
    const year = loi_utils.getYear(options);
    const email = options.email; // TODO: we could reject if the email in the token is different from the one provided as input to the command.
    // for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
    if (options.cross_country) provider = provider.split('.')[0];
    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);
    const fetch_ethereum = options.ethereum ? "1" : "null";

    var bg, mcl, FrTmp, G1Base, G2Base;
    if (fetch_ethereum === "null") {
        bg = require('@noble/curves/bls12-381').bls12_381;
        main();
    } else {
        bg = require('@noble/curves/bn254').bn254;
        mcl = require('mcl-wasm');
        mcl.init(mcl.BN_SNARK1).then(() => {
            G1Base = mcl_bases.G1Base();
            G2Base = mcl_bases.G2Base();
            main();
        }).catch((err) => {
            console.error(err.message);
            process.exit(1);
        });
    }

    function main() {
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


        loi_utils.read(process.stdin).then(function(msg) {
            var randtmp = bg.utils.randomPrivateKey();
            var derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32); // 48 bytes for 32-bytes input

            const fp = mod.Field(fetch_ethereum === 'null' ? bg.params.r : bg.CURVE.n);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                //   FrTmp.setStr(utils.bytesToHex(derived), 16);
                FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
            }
            const r = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp;
            const C = fetch_ethereum === 'null' ? mpk.multiply(r) : mcl.mul(mpk, r);
            const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
            const h = eth.hashToCurve(id, fetch_ethereum, fetch_ethereum === 'null' ? bg : mcl);
            const E = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.BASE.multiply(r) : mcl.mul(G1Base, r);
            const F = fetch_ethereum === 'null' ? token.multiply(r) : mcl.mul(token, r);
            randtmp = bg.utils.randomPrivateKey();
            derived = hkdf.hkdf(sha256.sha256, randtmp, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                //   FrTmp.setStr(utils.bytesToHex(derived), 16);
                FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
            }
            const a = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp;
            const pi_A = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.BASE.multiply(a) : mcl.mul(G1Base, a);
            const dot = hashes.utf8ToBytes(".");
            var input;
            if (options.hex) {
                msg = utils.hexToBytes(msg);
                input = fetch_ethereum === 'null' ? new Uint8Array(...hashes.utf8ToBytes(E.toHex() + "." + pi_A.toHex() + "."), ...msg, ...hashes.utf8ToBytes("." + email)) : new Uint8Array([...utils.hexToBytes(loi_utils.pad(E.getStr(16).split(' ')[1])), ...dot, ...utils.hexToBytes(loi_utils.pad(pi_A.getStr(16).split(' ')[1])), ...dot, ...msg, ...dot, ...hashes.utf8ToBytes(email)]); // we hash input = statement E + first message pi_A + message msg + email. TODO: we should hash id instead of email
            } else input = fetch_ethereum === 'null' ? hashes.utf8ToBytes(E.toHex() + "." + pi_A.toHex() + "." + msg + "." + email) : new Uint8Array([...utils.hexToBytes(loi_utils.pad(E.getStr(16).split(' ')[1])), ...dot, ...utils.hexToBytes(loi_utils.pad(pi_A.getStr(16).split(' ')[1])), ...dot, ...hashes.utf8ToBytes(msg), ...dot, ...hashes.utf8ToBytes(email)]); // we hash input = statement E + first message pi_A + message msg + email. TODO: we should hash id instead of email
            //TODO: we should hash id instead of email
            derived = fetch_ethereum === 'null' ? hkdf.hkdf(sha256.sha256, input, undefined, 'application', 48) : sha256.sha256(input); // 48 bytes for 32-bytes input - for bn254 we use sha256 to ease verification on-chain
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                //   FrTmp.setStr(utils.bytesToHex(derived), 16);
                FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
            }
            const e = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp; // e is the hash of input converted to scalar
            const pi_z = fetch_ethereum === 'null' ? fp.add(a, fp.mul(e, r)) : mcl.add(a, mcl.mul(e, r)); // pi_z = a + e*r
            var signature;
            if (!options.json)
                signature = fetch_ethereum === 'null' ? C.toHex() + "." + E.toHex() + "." + F.toHex() + "." + pi_A.toHex() + "." + utils.numberToHexUnpadded(pi_z) : C.getStr(16) + "." + E.getStr(16) + "." + F.getStr(16) + "." + pi_A.getStr(16) + "." + pi_z.getStr(16);
            else {
                signature = fetch_ethereum !== 'null' ?
                    "{\n" +
                    "   \"signature\": {\n" +
                    "     \"asTuple\": \"[[[" + C.getStr(10).split(' ')[2] + "," + C.getStr(10).split(' ')[1] + "],[" + C.getStr(10).split(' ')[4] + "," + C.getStr(10).split(' ')[3] + "]],[" + E.getStr(10).split(' ')[1] + "," +
                    E.getStr(10).split(' ')[2] + "],[" + F.getStr(10).split(' ')[1] + "," + F.getStr(10).split(' ')[2] + "],[" + pi_A.getStr(10).split(' ')[1] + "," + pi_A.getStr(10).split(' ')[2] + "]," + pi_z.getStr() + "]\",\n" +
                    "     \"C\":       \"" + C.getStr(16) + "\",\n" +
                    "     \"Cx1\":     \"" + C.getStr(16).split(' ')[1] + "\",\n" +
                    "     \"Cx2\":     \"" + C.getStr(16).split(' ')[2] + "\",\n" +
                    "     \"Cy1\":     \"" + C.getStr(16).split(' ')[3] + "\",\n" +
                    "     \"Cy2\":     \"" + C.getStr(16).split(' ')[4] + "\",\n" +
                    "     \"E\":       \"" + E.getStr(16) + "\",\n" +
                    "     \"Ex\":      \"" + E.getStr(16).split(' ')[1] + "\",\n" +
                    "     \"Ey\":      \"" + E.getStr(16).split(' ')[2] + "\",\n" +
                    "     \"F\":       \"" + F.getStr(16) + "\",\n" +
                    "     \"Fx\":      \"" + F.getStr(16).split(' ')[1] + "\",\n" +
                    "     \"Fy\":      \"" + F.getStr(16).split(' ')[2] + "\",\n" +
                    "     \"pi_A\":    \"" + pi_A.getStr(16) + "\",\n" +
                    "     \"pi_Ax\":   \"" + pi_A.getStr(16).split(' ')[1] + "\",\n" +
                    "     \"pi_Ay\":   \"" + pi_A.getStr(16).split(' ')[2] + "\",\n" +
                    "     \"pi_z\":    \"" + pi_z.getStr(16) + "\"\n" +
                    "   }\n" +
                    "}" :
                    "{\n" +
                    "   \"signature\": {\n" +
                    "     \"C\":    \"" + C.toHex() + "\",\n" +
                    "     \"Cx1\":  \"" + C.toHex().slice(0, 96) + "\",\n" +
                    "     \"Cx2\":  \"" + C.toHex().slice(96, 192) + "\",\n" +
                    "     \"E\":    \"" + E.toHex() + "\",\n" +
                    "     \"F\":    \"" + F.toHex() + "\",\n" +
                    "     \"pi_A\": \"" + pi_A.toHex() + "\",\n" +
                    "     \"pi_z\": \"" + utils.numberToHexUnpadded(pi_z) + "\"\n" +
                    "   }\n" +
                    "}";
            }
            if (!options.output_signature) console.log("signature: " + signature);
            else {

                console.log("DEBUG: signature written to file " + options.output_signature);
                Log.log(signature);
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