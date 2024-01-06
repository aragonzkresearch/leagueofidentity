const bls = require("@noble/curves/bls12-381");
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");

function ComputeTokenShare(email, share, month, year, group, provider, fetch_friends, anon) {
    try {
        console.log("token share to transmit to client: " + share);
        var share_decoded = utils.bytesToNumberBE(utils.hexToBytes(share));
        pk = bls.bls12_381.G2.ProjectivePoint.BASE.multiply(share_decoded);
        if (group === "1" && anon === "0") email = email.split('@')[1];
        const msg = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + anon);
        var hash = bls.bls12_381.G1.hashToCurve(msg);
        hash = hash.multiply(share_decoded);
        return "LoI.." + provider + ".." + Buffer.from(email, 'utf8').toString('hex') + ".." + month + ".." + year + ".." + pk.toHex() + ".." + hash.toHex() + ".." + fetch_friends + ".." + anon;
    } catch (err) {

        console.error(err);
    }
}
module.exports = {
    ComputeTokenShare,
}