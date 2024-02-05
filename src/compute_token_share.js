const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const eth = require("./ethereum_mode");
const mcl_bases = require("./mcl_bases");

function ComputeTokenShare(email, share, month, year, group, provider, fetch_friends, anon, ethereum) {
    var bg, mcl;
    try {
        if (ethereum === "null") {
            bg = require('@noble/curves/bls12-381').bls12_381;
            return main(bg, email, share, month, year, group, provider, fetch_friends, anon, ethereum);
        } else {

            mcl = require('mcl-wasm');
            return mcl.init(mcl.BN_SNARK1).then(() => {
                return main(mcl, email, share, month, year, group, provider, fetch_friends, anon, ethereum);
            }).catch((err) => {
                console.error(err.message);
                process.exit(1);
            });
        }
    } catch (err) {
        console.error(err.message);
    }

}

function main(grp, email, share, month, year, group, provider, fetch_friends, anon, ethereum) {
    var FrTmp;
    var G2Base;
    try {
        console.log("token share to transmit to client: " + share);
        if (ethereum !== 'null') {
            G2Base = mcl_bases.G2Base();
            FrTmp = new grp.Fr();
            FrTmp.setStr(share, 16);
        }
        var share_decoded = ethereum === 'null' ? utils.bytesToNumberBE(utils.hexToBytes(share)) : FrTmp;
        pk = ethereum === 'null' ? grp.G2.ProjectivePoint.BASE.multiply(share_decoded) : grp.mul(G2Base, share_decoded);
        if (group === "1" && anon === "0") email = email.split('@')[1];
        const msg = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + anon + ".." + ethereum);
        //var hash = bg.G1.hashToCurve(msg);
        var hash = eth.hashToCurve(msg, ethereum, grp);
        hash = ethereum === 'null' ? hash.multiply(share_decoded) : grp.mul(hash, share_decoded);
        return ethereum === 'null' ? "LoI.." + provider + ".." + Buffer.from(email, 'utf8').toString('hex') + ".." + year + ".." + month + ".." + pk.toHex() + ".." + hash.toHex() + ".." + fetch_friends + ".." + anon + ".." + ethereum : "LoI.." + provider + ".." + Buffer.from(email, 'utf8').toString('hex') + ".." + year + ".." + month + ".." + pk.getStr(16) + ".." + hash.getStr(16) + ".." + fetch_friends + ".." + anon + ".." + ethereum;
    } catch (err) {
        console.error(err.message);
    }
}
module.exports = {
    ComputeTokenShare,
}