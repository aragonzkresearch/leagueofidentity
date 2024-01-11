// NOT SUPPORTED YET.
//  Unfortunately, noble does not fully support bn254. We leave this option in the case one day noble will introduce full support for bn254. However, notice that if in next upgrades Ethereum will adopt bls12 there will no need for bn254. 
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");

function hashToCurve(id, ethereum_mode) {
    if (ethereum_mode === "null") {
        const bg = require('@noble/curves/bls12-381').bls12_381;
        return bg.G1.hashToCurve(id);
    } else {
        // TODO: FINISH
        const bg = require('@noble/curves/bn254');
        return bg.G1.hashToCurve(id);
    }
}

function hashToCurveWithWitness(id, y) {
    // TODO: FINISH
}

module.exports = {
    hashToCurve,
    hashToCurveWithWitness,
}
