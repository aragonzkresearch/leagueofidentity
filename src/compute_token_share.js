const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const eth = require("./ethereum_mode");

function ComputeTokenShare(email, share, month, year, group, provider, fetch_friends, anon, ethereum) {
    var bg;
    if (ethereum === "null") bg = require('@noble/curves/bls12-381').bls12_381;
    else bg = require('@noble/curves/bn254').bn254;
    try {
        console.log("token share to transmit to client: " + share);
        var share_decoded = utils.bytesToNumberBE(utils.hexToBytes(share));
        pk = bg.G2.ProjectivePoint.BASE.multiply(share_decoded);
        if (group === "1" && anon === "0") email = email.split('@')[1];
        const msg = hashes.utf8ToBytes("LoI.." + provider + ".." + email + ".." + month + ".." + year + ".." + fetch_friends + ".." + anon + ".." + ethereum);
        //var hash = bg.G1.hashToCurve(msg);
        var hash = eth.hashToCurve(msg, ethereum);
        hash = hash.multiply(share_decoded);
        return "LoI.." + provider + ".." + Buffer.from(email, 'utf8').toString('hex') + ".." + month + ".." + year + ".." + pk.toHex() + ".." + hash.toHex() + ".." + fetch_friends + ".." + anon + ".." + ethereum;
    } catch (err) {

        console.error(err);
    }
}
module.exports = {
    ComputeTokenShare,
}