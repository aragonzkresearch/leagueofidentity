// NOT SUPPORTED YET.
//  Unfortunately, noble does not fully support bn254. We leave this option in the case one day noble will introduce full support for bn254. However, notice that if in next upgrades Ethereum will adopt bls12 there will no need for bn254. 
const hkdf = require("@noble/hashes/hkdf");
const sha256 = require("@noble/hashes/sha256");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");

function hashToCurve(id, ethereum_mode, grp) {
    if (ethereum_mode === "null") {
        return grp.G1.hashToCurve(id);
    } else {
        //console.log(id);
        //console.log(utils.numberToHexUnpadded(utils.bytesToNumberBE(id)));
        bg = require('@noble/curves/bn254').bn254;
        const fp = mod.Field(bg.CURVE.Fp.ORDER);
        const derived = sha256.sha256(id);
        var three = fp.create(3n);
        var one = fp.create(1n);
        var x = fp.create(fp.fromBytes(derived));
        var y;
        while (true) {
            y = fp.mul(x, x);
            y = fp.mul(y, x);
            y = fp.add(y, three);
            try {
                y = fp.sqrt(y);
                break;
            } catch (err) {
                x = fp.add(x, one);
            }
        }
        var X = new grp.Fp();
        var Y = new grp.Fp();
        var Z = new grp.Fp();
        var P = new grp.G1();
        X.setStr(utils.bytesToHex(fp.toBytes(x)), 16);
        Y.setStr(utils.bytesToHex(fp.toBytes(y)), 16);
        Z.setStr("1");
        P.setX(X);
        P.setY(Y);
        P.setZ(Z);
        return P;
    }
}


module.exports = {
    hashToCurve,
}