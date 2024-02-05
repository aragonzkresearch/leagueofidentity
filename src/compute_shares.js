// node compute_shares.js -t t -n n
// t is the threshold who can reconstruct the master secret key and n is the number of nodes of LoI network
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const commander = require('commander');
const mcl_bases = require('./mcl_bases');

commander
    .version('1.0.0', '-v, --version')
    .usage('-t <value> -n <value>')
    .requiredOption('-t, --threshold <value>', 'threshold of nodes required to reconstruct the master secret key.')
    .requiredOption('-n, --no_nodes <value>', 'total number of nodes.')
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine. NOT SUPPORTED YET, DO NOT USE IT.')
    .parse(process.argv);

const options = commander.opts();
const fetch_ethereum = options.ethereum ? "1" : "null";

var bg;
if (fetch_ethereum === "null") {
    bg = require('@noble/curves/bls12-381').bls12_381;
    main();
} else {
    bg = require('@noble/curves/bn254').bn254;
    mcl = require('mcl-wasm');
    mcl.init(mcl.BN_SNARK1).then(() => {
        main();
    });
}

function main() {
    const fp = mod.Field(fetch_ethereum === 'null' ? bg.params.r : bg.CURVE.n);
    var G2Base;
    var FrTmp, FrTmp2;
    if (fetch_ethereum !== 'null') {
        G2Base = mcl_bases.G2Base();
        FrTmp = new mcl.Fr();
    }
    const A = [];
    const s = [];

    var privtmp;
    var derived;
    for (let i = 1; i < options.threshold; i++) {

        privtmp = bg.utils.randomPrivateKey();

        derived = hkdf.hkdf(sha256.sha256, privtmp, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32); // 48 bytes for 32-bytes input
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.Fr();
            FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
        }
        A[i] = fetch_ethereum === 'null' ? mod.hashToPrivateScalar(derived, bg.params.r) : FrTmp;
        console.log("DEBUG: " + i + "-th coefficient of the " + (options.threshold - 1) + "-degree polynomial: " + (fetch_ethereum === 'null' ? A[i] : A[i].getStr()));

    }
    privtmp = bg.utils.randomPrivateKey();
    derived = hkdf.hkdf(sha256.sha256, privtmp, undefined, 'application', fetch_ethereum === 'null' ? 48 : 32);
    //A[0] = mod.hashToPrivateScalar(derived, bg.params.r);
    if (fetch_ethereum !== 'null') {
        rTmp = new mcl.Fr();
        FrTmp.setStr(utils.numberToHexUnpadded(fp.create(utils.bytesToNumberBE(derived))), 16);
    }
    A[0] = fetch_ethereum === 'null' ? mod.hashToPrivateScalar(derived, bg.params.r) : FrTmp;
    console.log("master secret key: " + (fetch_ethereum === 'null' ? utils.bytesToHex(fp.toBytes(A[0])) : A[0].getStr(16)));
    //const mpk = bg.G2.ProjectivePoint.BASE.multiply(fp.create(A[0]));
    const mpk = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.BASE.multiply(fp.create(A[0])) : mcl.mul(G2Base, A[0]);
    console.log("master public key: " + (fetch_ethereum === 'null' ? mpk.toHex() : mpk.getStr(16)));

    var tmp;
    for (let i = 1n; i <= options.no_nodes; i++) {
        //tmp = fp.ZERO;
        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.Fr();
            FrTmp.setStr('0');
        }
        tmp = fetch_ethereum === 'null' ? fp.ZERO : FrTmp;

        if (fetch_ethereum !== 'null') {
            FrTmp = new mcl.Fr();
            FrTmp.setStr(i.toString());
        }
        //let I = fp.create(i);
        let I = fetch_ethereum === 'null' ? fp.create(i) : FrTmp;
        for (let j = 0n; j < options.threshold; j++) {
            //let J = fp.create(j);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                FrTmp.setStr(j.toString());
            }
            let J = fetch_ethereum === 'null' ? fp.create(j) : FrTmp;
            //let Aj = fp.create(A[j]);
            let Aj = fetch_ethereum === 'null' ? fp.create(A[j]) : A[j];
            //tmp = fp.add(fp.mul(Aj, fp.pow(I, J)), tmp);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                FrTmp.setStr(utils.bytesToHex(fp.toBytes(fp.pow(fp.create(i), fp.create(j)))), 16);
            }
            tmp = fetch_ethereum === 'null' ? fp.add(fp.mul(Aj, fp.pow(I, J)), tmp) : mcl.add(mcl.mul(Aj, FrTmp), tmp);
        }
        s[i] = tmp;
        console.log("share of the server " + i + ": " + (fetch_ethereum === 'null' ? utils.bytesToHex(fp.toBytes(s[i])) : s[i].getStr(16)));
    }

    function ComputeLagrangeCoefficients(lambda, t, Q, fetch_ethereum) {


        for (let i = 0n; i < t; i++) {
            //tmp = fp.create(1n);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                FrTmp.setInt(1);
            }
            tmp = fetch_ethereum === 'null' ? fp.create(1n) : FrTmp;
            I = fetch_ethereum === 'null' ? fp.create(Q[i]) : Q[i];
            for (let j = 0n; j < t; j++) {
                J = fetch_ethereum === 'null' ? fp.create(Q[j]) : Q[j];
                if (j == i) continue;

                if (fetch_ethereum !== 'null') {
                    FrTmp = new mcl.Fr();
                    FrTmp2 = new mcl.Fr();
                    FrTmp.setStr((J - I).toString());
                    FrTmp2.setStr(J.toString());
                }
                tmp = fetch_ethereum === 'null' ? fp.mul(fp.div(J, fp.sub(J, I)), tmp) : mcl.mul(mcl.div(FrTmp2, FrTmp), tmp);
            }
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                FrTmp.setStr(tmp.getStr());
            }
            lambda[Q[i]] = fetch_ethereum === 'null' ? tmp : FrTmp;

        }

    }
    var Q = [];
    var lambda = [];
    for (i = 0n; i < options.threshold; i++) Q[i] = i + 1n;
    //Q[0] = 1n;
    //Q[1] = 2n;
    //Q[2] = 4n;
    ComputeLagrangeCoefficients(lambda, options.threshold, Q, fetch_ethereum);
    const sk = [];
    const pk = [];
    tmp = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.BASE.subtract(bg.G2.ProjectivePoint.BASE) : mcl.sub(G2Base, G2Base);
    for (i = 0n; i < options.threshold; i++) {
        sk[Q[i]] = fetch_ethereum === 'null' ? fp.mul(s[Q[i]], lambda[Q[i]]) : mcl.mul(s[Q[i]], lambda[Q[i]]);
        pk[Q[i]] = fetch_ethereum === 'null' ? bg.G2.ProjectivePoint.BASE.multiply(sk[Q[i]]) : mcl.mul(G2Base, sk[Q[i]]);
        tmp = fetch_ethereum === 'null' ? tmp.add(pk[Q[i]]) : mcl.add(tmp, pk[Q[i]]);
    }

    console.log("reconstructed master public key: " + (fetch_ethereum === 'null' ? tmp.toHex() : tmp.getStr(16)));
    if (fetch_ethereum !== 'null') console.log("reconstructed master public key as Ethereum tuple: " + "[[" + tmp.getStr(10).split(' ')[2] + "," + tmp.getStr(10).split(' ')[1] + "],[" + tmp.getStr(10).split(' ')[4] + "," + tmp.getStr(10).split(' ')[3] + "]]");

}