const bls = require("@noble/curves/bls12-381");
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const dic_map = new Map();
const TIMEOUT_CHALLENGE = 1800;

function loi_server_dic(index, req, res) {
    dic_map.set("2.073e239b424905855426d8daad7ca69e944a902b633fc4d314cf10b65594ed4b.1703668410", true);
    dic_map.set("3.66cdfbb18ab5edc73a61b48a34a2034545dd3c8209beeddd48d9bbf44d2ae3f2.1703716227", true);
    const challenge = index + "." + utils.bytesToHex(bls.bls12_381.utils.randomPrivateKey()) + "." + Math.floor(Date.now() / 1000);
    //   var challenge;
    // if (index === "2") challenge = "2.229e58ed87e70adf74001e2943751723f35c7a5febb2440ff5d66689f580ea46.1703892168";
    // if (index === "3") challenge = "3.578edb265928f79b56b2ffd79a3237a66d420b155d5b8206236adba4adf675bf.1703892168";
    dic_map.set(challenge, true);
    res.send(challenge);
}
module.exports = {
    loi_server_dic,
    dic_map,
    TIMEOUT_CHALLENGE,
}