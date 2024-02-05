mcl = require('mcl-wasm');

function G1Base() {

    var X = new mcl.Fp();
    var Y = new mcl.Fp();
    var Z = new mcl.Fp();
    var P = new mcl.G1();
    X.setStr("0000000000000000000000000000000000000000000000000000000000000001", 16);
    Y.setStr("0000000000000000000000000000000000000000000000000000000000000002", 16);
    Z.setStr("1");
    P.setX(X);
    P.setY(Y);
    P.setZ(Z);
    //console.log(P.getStr());
    //console.log(P.isValid());
    return P;
}

function G2Base() {

    const x0 = new mcl.Fp()
    const x1 = new mcl.Fp()
    const y0 = new mcl.Fp()
    const y1 = new mcl.Fp()
    const z0 = new mcl.Fp()
    const z1 = new mcl.Fp()
    var X = new mcl.Fp2();
    var Y = new mcl.Fp2();
    var Z = new mcl.Fp2();
    var P = new mcl.G2();
    x1.setStr("198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2", 16);
    x0.setStr("1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED", 16);
    y1.setStr("090689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B", 16);
    y0.setStr("12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA", 16);
    z0.setInt(1);
    z1.setInt(0);
    X.set_a(x0);
    X.set_b(x1);
    Y.set_a(y0);
    Y.set_b(y1);
    Z.set_a(z0);
    Z.set_b(z1);
    P.setX(X);
    P.setY(Y);
    P.setZ(Z);
    //console.log(P.getStr());
    //console.log(P.isValid());
    return P;
}
module.exports = {
    G1Base,
    G2Base,
}