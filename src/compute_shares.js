// node compute_shares.js -t t -n n
// t is the threshold who can reconstruct the master secret key and n is the number of nodes of LoI network
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const commander = require('commander');

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
if (fetch_ethereum === "null") bg = require('@noble/curves/bls12-381').bls12_381;
else bg = require('@noble/curves/bn254').bn254;

const A = [];
const s = [];

var privtmp;
var derived;
for (let i = 1; i < options.threshold; i++) {

    privtmp = bg.utils.randomPrivateKey();

    derived = hkdf.hkdf(sha256.sha256, privtmp, undefined, 'application', 48); // 48 bytes for 32-byte input
    A[i] = mod.hashToPrivateScalar(derived, bg.params.r);
    console.log("DEBUG: " + i + "-th coefficient of the " + (options.threshold - 1) + "-degree polynomial: " + A[i]);

}

privtmp = bg.utils.randomPrivateKey();
derived = hkdf.hkdf(sha256.sha256, privtmp, undefined, 'application', 48);
A[0] = mod.hashToPrivateScalar(derived, bg.params.r);
const fp = mod.Field(bg.params.r);
console.log("master secret key: " + utils.bytesToHex(fp.toBytes(A[0])));
const mpk = bg.G2.ProjectivePoint.BASE.multiply(fp.create(A[0]));
console.log("master public key: " + mpk.toHex());

var tmp;
for (let i = 1n; i <= options.no_nodes; i++) {
    tmp = fp.ZERO;

    let I = fp.create(i);
    for (let j = 0n; j < options.threshold; j++) {
        let J = fp.create(j);
        let Aj = fp.create(A[j]);
        tmp = fp.add(fp.mul(Aj, fp.pow(I, J)), tmp);
    }
    s[i] = tmp;
    console.log("share of the server " + i + ": " + utils.bytesToHex(fp.toBytes(s[i])));
}


function ComputeLagrangeCoefficients(lambda, t, Q) {


    for (let i = 0n; i < t; i++) {
        tmp = fp.create(1n);
        I = fp.create(Q[i]);
        for (let j = 0n; j < t; j++) {
            J = fp.create(Q[j]);
            if (j == i) continue;
            tmp = fp.mul(fp.div(J, fp.sub(J, I)), tmp);
        }
        lambda[Q[i]] = tmp;

    }

}
var Q = [];
var lambda = [];
for (i = 0n; i < options.threshold; i++) Q[i] = i + 1n;
//Q[0] = 1n;
//Q[1] = 2n;
//Q[2] = 4n;
ComputeLagrangeCoefficients(lambda, options.threshold, Q);
const sk = [];
const pk = [];
tmp = bg.G2.ProjectivePoint.BASE.subtract(bg.G2.ProjectivePoint.BASE);
for (i = 0n; i < options.threshold; i++) {
    sk[Q[i]] = fp.mul(s[Q[i]], lambda[Q[i]]);
    pk[Q[i]] = bg.G2.ProjectivePoint.BASE.multiply(sk[Q[i]]);
    tmp = tmp.add(pk[Q[i]]);
}

console.log("reconstructed master public key: " + tmp.toHex());