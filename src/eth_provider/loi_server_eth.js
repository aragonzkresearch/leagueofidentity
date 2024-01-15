const {
    Web3
} = require("web3");
const cts = require("../compute_token_share");

function loi_server_eth(req, res, TIMEOUT_CHALLENGE, INFURA_API_KEY, SignMessage, options) {
    if (req.params.group === "1") {
        console.error("Token request with group param 1 for provider eth.");
        res.sendStatus(400);
        return;
    }
    const time = req.params.token.split(':')[0];
    if (Math.floor(Date.now() / 1000) - time >= TIMEOUT_CHALLENGE) {
        console.error("Error. Expired token for provider eth.");
        res.sendStatus(400);
        return;

    }
    const network = process.env.ETHEREUM_NETWORK;
    const web3 = new Web3(
        new Web3.providers.HttpProvider(INFURA_API_KEY, network),
    );
    const signature = req.params.token.split(':')[2];
    const addr = req.params.token.split(':')[1];
    const msg = SignMessage + time + ":" + addr;
    const RecoveredAddr = web3.eth.accounts.recover(msg, signature);
    if (RecoveredAddr !== addr) {
        console.error("Error. Invalid signature.");
        res.sendStatus(400);
        return;
    }
    web3.eth.getBalance(RecoveredAddr).then(function(wei) {
        if (req.params.friends !== "null" && wei < req.params.friends) {
            console.error("Error. Invalid address or balance.");
            res.sendStatus(400);
            return;

        }
        if (req.params.anon === "1") wei = 0n;
        const Email = wei + "@" + RecoveredAddr;
        console.log("Received request for email: " + Email + " for provider: " + req.params.prov + " and group flag: " + req.params.group + " and friends param: " + req.params.friends + " and anon param: " + req.params.anon + " and ethereum mode: " + req.params.ethereum);
        var year, month, curyear, curmnonth;
        const date = new Date();
        curyear = date.getFullYear();
        curmonth = date.getMonth();
        if (req.params.date !== "now") {
            year = req.params.date.split('.')[1];
            month = req.params.date.split('.')[0];
            if (year > curyear || month > curmonth) {
                console.error("Invalid token request received by client.");
                res.sendStatus(400);
                return;
            }
        } else {
            year = curyear;
            month = curmonth;
        }
        const st = cts.ComputeTokenShare(Email, options.share, month, year, req.params.group, req.params.prov, req.params.friends, req.params.anon, req.params.ethereum);
        res.send(st);

    }).catch(function(err) {
        console.error("Invalid token request received by client.");
        res.sendStatus(400);
        return;
    });



}


module.exports = {
    loi_server_eth,
}