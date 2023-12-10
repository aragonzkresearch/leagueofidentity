// node compute_shares.js t n
// t is the threshold who can reconstruct the master secret key and n is the number of nodes of LoI network
const bls = require("@noble/curves/bls12-381");
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");


const A = [];
const s = [];
var privtmp;
var derived;
for (let i = 1; i < process.argv[2]; i++) {

    privtmp = bls.bls12_381.utils.randomPrivateKey();

    derived = hkdf.hkdf(sha256.sha256, privtmp, undefined, 'application', 48); // 48 bytes for 32-byte privtmp
    A[i] = mod.hashToPrivateScalar(derived, bls.bls12_381.params.r);
    console.log("DEBUG: " + i + "-th coefficient of the " + (process.argv[2] - 1) + "-degree polynomial: " + A[i]);

}

privtmp = bls.bls12_381.utils.randomPrivateKey();
derived = hkdf.hkdf(sha256.sha256, privtmp, undefined, 'application', 48); // 48 bytes for 32-byte privtmp
A[0] = mod.hashToPrivateScalar(derived, bls.bls12_381.params.r);
const fp = mod.Field(bls.bls12_381.params.r);
console.log("master secret key: " + utils.bytesToHex(fp.toBytes(A[0])));
const mpk = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(fp.create(A[0]));
console.log("master public key: " + mpk.toHex());

var tmp;
for (let i = 1n; i <= process.argv[3]; i++) {
    tmp = fp.ZERO;

    let I = fp.create(i);
    for (let j = 0n; j < process.argv[2]; j++) {
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
for (i = 0n; i < process.argv[2]; i++) Q[i] = i + 1n;
Q[0] = 1n;
Q[1] = 2n;
Q[2] = 4n;
ComputeLagrangeCoefficients(lambda, process.argv[2], Q);
const sk = [];
const pk = [];
tmp = bls.bls12_381.G2.ProjectivePoint.BASE.subtract(bls.bls12_381.G2.ProjectivePoint.BASE);
for (i = 0n; i < process.argv[2]; i++) {
    sk[Q[i]] = fp.mul(s[Q[i]], lambda[Q[i]]);
    pk[Q[i]] = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(sk[Q[i]]);
    tmp = tmp.add(pk[Q[i]]);
}

console.log("reconstructed master public key: " + tmp.toHex());
