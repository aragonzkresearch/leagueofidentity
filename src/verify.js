// usage:
// node verify.js -k mpk -e email (or domain/phone) -m month.year -s signature [OPTIONS]
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
    .usage('-k <value> -e <value> -m <value> -s <value> [OPTIONS]')
    .requiredOption('-k, --key <value>', 'the master public key.')
    .requiredOption('-e, --email <value>', 'email. This value may also be a domain when used in combination with tokens obtained by get_token.js with the -g option or may also be a phone number for \"google.phone\" provider.')
    .requiredOption('-s, --signature <value>', 'the signature.')
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\", \"eth\", \"nintendo\"). Default is \"google\".')
    .option('-or, --output_result <value>', 'write the result (\"0\" or \"1\") to the file <value> instead of writing it to the stdout.')
    .option('-anon, --anonymous', 'for tokens granted through the \'--anonymous\' option.')
    .option('-f, --friends <value>', 'For \"facebook\" provider grant the token only to a user with at least <value> total counts of friends. For \"eth\" provider grant the token only to an Ethereum address with at least <value> of Wei held by the address.')
    .option('-j, --json', 'Parse the signature in JSON format.')
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
        stdout: options.output_result ? fs.createWriteStream(options.output_result) : process.stdout,
        stderr: process.stderr,
    });
    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);
    const fetch_ethereum = options.ethereum ? "1" : "null";

    // for DIC only: if the options cross_country is set change the provider e.g. dic.it to just dic
    if (options.cross_country) provider = provider.split('.')[0];
    if (options.json) {

        const data = JSON.parse(options.signature);
        options.signature = data.signature.C + "." + data.signature.E + "." + data.signature.F + "." + data.signature.pi_A + "." + data.signature.pi_z;
    }
    const month = loi_utils.getMonth(options);
    const year = loi_utils.getYear(options);
    const email = options.email;
    const signature = options.signature;

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
            FrTmp = new mcl.G2();
            FrTmp.setStr(signature.split('.')[0], 16);
        }
        const C = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.fromHex(signature.split('.')[0]) : FrTmp;
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.G1();
            FrTmp.setStr(signature.split('.')[1], 16);
        }
        const E = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.fromHex(signature.split('.')[1]) : FrTmp;
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.G1();
            FrTmp.setStr(signature.split('.')[2], 16);
        }
        const F = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.fromHex(signature.split('.')[2]) : FrTmp;
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.G1();
            FrTmp.setStr(signature.split('.')[3], 16);
        }
        const pi_A = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.fromHex(signature.split('.')[3]) : FrTmp;
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.Fr();
            FrTmp.setStr(signature.split('.')[4], 16);
        }
        const pi_z = fetch_ethereum === 'null' ? utils.hexToNumber(signature.split('.')[4]) : FrTmp;
        loi_utils.read(process.stdin).then(function(msg) {
            const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum);
            const h = eth.hashToCurve(id, fetch_ethereum, fetch_ethereum === 'null' ? bg : mcl);
            var flag = 1;
            var t1 = (fetch_ethereum === 'null' ? bg : mcl).pairing(h, C);
            var t2 = fetch_ethereum === 'null' ? bg.pairing(F, bg.G2.ProjectivePoint.BASE) : mcl.pairing(F, G2Base);
            if (fetch_ethereum === 'null' ? (bg.fields.Fp12.eql(t1, t2) == false) : !t1.isEqual(t2)) flag = 0;
            else {
                t1 = (fetch_ethereum === 'null' ? bg : mcl).pairing(E, mpk);
                t2 = fetch_ethereum === 'null' ? bg.pairing(bg.G1.ProjectivePoint.BASE, C) : mcl.pairing(G1Base, C);
                if (fetch_ethereum === 'null' ? (bg.fields.Fp12.eql(t1, t2) == false) : !t1.isEqual(t2)) flag = 0;
                else { // TODO: note that here there is redundancy in the computation because we first deserialize and then we re-serialize to hex
                    const dot = hashes.utf8ToBytes(".");
                    var input;
                    if (options.hex) {
                        msg = utils.hexToBytes(msg);
                        input = fetch_ethereum === 'null' ? new Uint8Array(...hashes.utf8ToBytes(E.toHex() + "." + pi_A.toHex() + "."), ...msg, ...hashes.utf8ToBytes("." + email)) : new Uint8Array([...utils.hexToBytes(loi_utils.pad(E.getStr(16).split(' ')[1])), ...dot, ...utils.hexToBytes(loi_utils.pad(pi_A.getStr(16).split(' ')[1])), ...dot, ...msg, ...dot, ...hashes.utf8ToBytes(email)]); // we hash input = statement E + first message pi_A + message msg + email. TODO: we should hash id instead of email
                    } else input = fetch_ethereum === 'null' ? hashes.utf8ToBytes(E.toHex() + "." + pi_A.toHex() + "." + msg + "." + email) : new Uint8Array([...utils.hexToBytes(loi_utils.pad(E.getStr(16).split(' ')[1])), ...dot, ...utils.hexToBytes(loi_utils.pad(pi_A.getStr(16).split(' ')[1])), ...dot, ...hashes.utf8ToBytes(msg), ...dot, ...hashes.utf8ToBytes(email)]); // we hash input = statement E + first message pi_A + message msg + email. TODO: we should hash id instead of email
                    const fp = mod.Field(fetch_ethereum === 'null' ? bg.params.r : bg.CURVE.n);
                    const derived = fetch_ethereum === 'null' ? hkdf.hkdf(sha256.sha256, input, undefined, 'application', 48) : sha256.sha256(input); // 48 bytes for 32-bytes input
                    if (fetch_ethereum !== 'null') {
                        FrTmp = new mcl.Fr();
                        //           FrTmp.setStr(utils.bytesToHex(derived), 16);
                        FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
                    }
                    const e = fetch_ethereum === 'null' ? fp.create(mod.hashToPrivateScalar(derived, bg.params.r)) : FrTmp; // e is the hash of input converted to scalar
                    const g1_z = fetch_ethereum === 'null' ? bg.G1.ProjectivePoint.BASE.multiply(pi_z) : mcl.mul(G1Base, pi_z);
                    const tmp = fetch_ethereum === 'null' ? E.multiply(e) : mcl.mul(E, e);
                    const tmp2 = fetch_ethereum === 'null' ? pi_A.add(tmp) : mcl.add(pi_A, tmp);
                    if (fetch_ethereum === 'null' && !g1_z.equals(tmp2)) flag = 0;
                    if (fetch_ethereum !== 'null' && g1_z.getStr(16) !== tmp2.getStr(16)) flag = 0;
                }
            }
            if (!options.output_result) console.log("result: " + flag);
            else {

                console.log("DEBUG: result written to file " + options.output_result);
                Log.log(flag);
            }
            process.exit(1 - flag);
        }).catch((err) => {
            console.error(err.message);
            process.exit(1);
        });
    }
} catch (err) {
    console.error(err.message);
    process.exit(1);
}