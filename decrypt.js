// usage:
// node decrypt.js token mpk email (or domain) month.year ciphertext

const bls = require('@noble/curves/bls12-381');
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const bls_verify = require("@noble/curves/abstract/bls");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const month = process.argv[5].split('.')[0];
const year = process.argv[5].split('.')[1];
const provider = "google";
const token = bls.bls12_381.G1.ProjectivePoint.fromHex(process.argv[2]);
const mpk = bls.bls12_381.G2.ProjectivePoint.fromHex(process.argv[3]);
const email = process.argv[4];
const ciphertext = process.argv[6];
const A = bls.bls12_381.G2.ProjectivePoint.fromHex(ciphertext.split('.')[1]);
const B = ciphertext.split('.')[2];
const length = parseInt(ciphertext.split('.')[0]);


const id = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year);
const h = bls.bls12_381.G1.hashToCurve(id);
const t1 = bls.bls12_381.pairing(h, mpk);
const t2 = bls.bls12_381.pairing(token, bls.bls12_381.G2.ProjectivePoint.BASE);
if (bls.bls12_381.fields.Fp12.eql(t1, t2) == false) {
    console.log("Verification of reconstructed token: failure.");
    return;
}
console.log("reconstructed token: " + token.toHex());
console.log("Verification of reconstructed token: success.");
const g_id = bls.bls12_381.pairing(token, A);
var B_computed = bls.bls12_381.fields.Fp12.toBytes(g_id);

const B_expanded = hkdf.hkdf(sha256.sha256, B_computed, undefined, 'application', length);
B_computed = hashes.bytesToHex(B_expanded);
var decoder = new TextDecoder();
console.log(decoder.decode(utils.hexToBytes(xor(B_computed, B))));

function xor(hex1, hex2) {
    const buf1 = Buffer.from(hex1, 'hex');
    const buf2 = Buffer.from(hex2, 'hex');
    const bufResult = buf1.map((b, i) => b ^ buf2[i]);
    return bufResult.toString('hex');
}