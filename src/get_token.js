// for usage see: https://github.com/aragonzkresearch/leagueofidentity/tree/master
// The file params.json contains configuration directive, in particular here we will use TIMEOUT_CHALLENGE for the digital identity card module 
const hashes = require("@noble/hashes/utils");
const utils = require("@noble/curves/abstract/utils");
const mod = require("@noble/curves/abstract/modular");
const fetch = require("node-fetch");
const commander = require('commander');
const loi_utils = require("./utils");
const nintendo = require("./nintendo_session_token_code");
const eth = require("./ethereum_mode");
const request = require("request");
const dic = require("./dic/loi_server_dic");
const mcl_bases = require("./mcl_bases");
const {
    Console
} = require('console');
const fs = require('fs');

commander
    .version('1.0.0', '-v, --version')
    .usage('-A <value> -t <value> -n <value> -l list [OPTIONS]')
    .requiredOption('-A, --access_token <value>', 'access token. For digital identity cards providers use \'-A null\'')
    .requiredOption('-t, --threshold <value>', 'threshold of nodes required to reconstruct the master secret key.')
    .requiredOption('-n, --no_nodes <value>', 'total number of nodes.')
    .requiredOption('-l, --list <value...>', 'list of t values of the form i_1 server_1:port_1 ... i_t server_t:port_t, where t is the given threshold specified by the -t argument and each index i_1, ..., i_t is an integer between 1 and n, where n is the value specified by the -n argument.')
    .option('-m, --month <value>', 'a value of the form month.year (XX.YYYY), where month is a value between 0 and 11. If not specified it defaults to the current month.year.')
    .option('-g, --group', 'request a group token.')
    .option('-P, --provider <value>', 'provider (\"google\", \"facebook\", \"google.phone\", \"dic.it\", \"eth\", \"nintendo\"). Default is \"google\".')
    .option('-ok, --output_key <value>', 'write the master public key to the file <value> instead of writing it to stdout.')
    .option('-ot, --output_token <value>', 'write the token to the file <value> instead of writing it to stdout.')
    .option('-f, --friends <value>', 'For \"facebook\" provider grant the token only to a user with at least <value> total counts of friends. For \"eth\" provider grant the token only to an Ethereum address with at least <value> of Wei held by the address.')
    .option('-anon, --anonymous', 'Use the access token AT specified to the argument -A as identity in order to achieve anonymity. You will need to specify the argument \'-e AT\' to all other commands and \'-e AT@domain\' when the the access token is obtained by using this command with the option \'-anon\' in combination with \'-g\'. For digital identity cards (DICs) this options is instead used to select the most anonymous form of identifier  obtainable from the DIC depending on the version and country of the card.')
    .option('-j, --json <value>', 'For digital identity cards (DICs): store the JSON file in the file named <value> . The file <value> needs to be signed by the user with his/her own DIC and then this command has to be called again with the option \'-s <file>\', where <file> is the signed file (usually with extension .p7m) generated by signing the file <value>. If this option is not set the content of the file is printed to the stdout.')
    .option('-s, --signature <value>', 'For digital identity cards (DICs) only: if this option is set, perform an authentication by sending the content of the file <value> signed by the user with his/her own DIC. The file to be signed is generated by first calling this command without this option.')
    .option('-age, --age <value>', 'For digital identity cards (DICs): grant the token only to users born in the year <value> or after if <value> is a positive integer or to users born in the year <-value> or earlier if <value> is a negative integer. A token obtained using this option has to be used with the encrypt, decrypt, sign and verify commands specifying an email of the type \'year@id\', where \'id\' can be the SSN of the user or other information (depending on whether the \'--anon\' option is used), and where <year> is either a four character integer specifying a year of birth (e.g. \'1991\') or a five characters string consisting of the minus sign (\'-\') followed by a four character integer specifying an year of birth (e.g., \'-1991\').')
    .option('-cc, --cross_country', 'For digital identity cards (DICs) only: if this option is set the provider info used to perform cryptographic operations will be shortned to \'dic\' rather than e.g., \'dic.it\'. In this way, a token for e.g. a Spanish DIC and an Italian DIC will correspond to the same provider (i.e., \'dic\'). Even if this option is used you must anyway specify the full provider (e.g., \'dic.it\') in order to perform operations that are country specific.')
    .option('-eth, --ethereum', 'Use Ethereum mode to achieve efficient verifiability on the Ethereum virtual machine.')
    .parse(process.argv);
try {
    const options = commander.opts();
    var provider;
    provider = loi_utils.handleProviders(options, provider);
    if (options.list.length != options.threshold * 2) {
        commander.help({
            error: true
        });
        return;
    }
    var LogMPK, LogTok, LogDIC;
    LogMPK = new Console({
        stdout: options.output_key ? fs.createWriteStream(options.output_key) : process.stdout,
        stderr: process.stderr,
    });
    LogTok = new Console({
        stdout: options.output_token ? fs.createWriteStream(options.output_token) : process.stdout,
        stderr: process.stderr,
    });
    LogJSON = new Console({
        stdout: options.json ? fs.createWriteStream(options.json) : process.stdout,
        stderr: process.stderr,
    });
    var Indices = [];
    var Addresses = [];
    for (let i = 0; i < options.threshold; i++) {
        let k = parseInt(options.list[i * 2]);
        if (k > options.no_nodes || k < 1) {
            commander.help({
                error: true
            }).catch(function(err) {
                console.error(err.message);
            });
            return;
        }
        Indices[i] = options.list[i * 2];
        Addresses[i] = options.list[i * 2 + 1];
    }
    const group = !options.group ? "0" : "1";
    if (group === "1" && (provider === 'google.phone' || provider === 'eth' || provider === "nintendo" || loi_utils.prov_is_dic(provider))) {
        console.error("Option --group is not compatible with provider " + provider + ".");
        process.exit(1);

    }
    const Month = !options.month ? "now" : options.month; // Month is "now" or a string of the form month.year with month between 0 and 11 and year of the form XXXX
    var flag = 1;
    var email, Provider, month, year;
    var pk = [];
    var hash = [];
    var Q = [];
    var DIC_Challenge = [];
    var lambda = [];
    var date_path;
    if (Month !== "now") {
        date_path = Month;
        month = Month.split('.')[0];
        year = Month.split('.')[1];
    } else date_path = "now";

    var t = options.threshold;

    if (options.friends && provider !== "eth" && provider !== "facebook") {
        console.error("Option --friends compatibile only with providers \"facebook\", \"eth\" but request is for provider: " + provider);
        process.exit(1);
    }

    if (options.anonymous && provider === "nintendo") {
        console.error("Option --anonymous not compatibile with provider \"nintendo\" but request is for provider: " + provider);
        process.exit(1);
    }

    var signed_file = '';
    var stream = '';
    if (options.signature) {
        stream = fs.createReadStream(options.signature);
        if (!loi_utils.prov_is_dic(provider)) {

            console.error("options --signature compatible only with digital identity cards providers.");
            process.exit(1);
        }


        stream.on('data', (chunk) => {
            signed_file = chunk;
        }).catch(function(err) {
            console.error(err.message);
        });

    }
    const fetch_friends = loi_utils.handleOptionFriends(options, provider);
    const fetch_anon = loi_utils.handleOptionAnon(options, provider);
    const fetch_age = options.age ? options.age : "null";
    const fetch_cross_country = options.cross_country ? "1" : "null";
    const fetch_ethereum = options.ethereum ? "1" : "null";
    if (provider === "nintendo") options.access_token = nintendo.nintendo_session_token_code(options.access_token);

    var bg, mcl, FrTmp, G1Base, G2Base;
    if (fetch_ethereum === "null") {
        bg = require('@noble/curves/bls12-381').bls12_381;
        main(bg);
    } else {
        bg = require('@noble/curves/bls12-381').bls12_381;

        mcl = require('mcl-wasm');
        mcl.init(mcl.BN_SNARK1).then(() => {
            G1Base = mcl_bases.G1Base();
            G2Base = mcl_bases.G2Base();
            main(mcl);
        }).catch(function(err) {
            console.error(err.message);
        });
    }

    function main(grp) {
        for (let i = 0; i < options.threshold; i++) {
            Q[i] = BigInt(Indices[i]);
            if (options.signature) {
                stream.on('end', () => {
                    const options = {
                        uri: Addresses[i] + "/dic/" + date_path + "/" + loi_utils.dic_country(provider) + "/" + fetch_anon + "/" + fetch_age + "/" + fetch_cross_country + "/" + fetch_ethereum,
                        body: signed_file,
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/octet-stream'
                        }
                    };
                    request(options, function(error, response, body) {
                        if (body === "ERROR") {
                            console.error("Error: the server " + Indices[i] + " refused to issue the token in response to the submitted signed document. This may be due to an invalid signature or a timeout.");
                            process.exit(1);
                        } else {
                            console.log("DEBUG: the server " + Indices[i] + " accepted the signed document.");
                            console.log(body);
                            if (!email) email = Buffer.from(utils.hexToBytes(body.split('..')[2])).toString('utf8');
                            else if (Buffer.from(utils.hexToBytes(body.split('..')[2])).toString('utf8') != email) throw ("Inconsistent values received from different servers");
                            if (!month) {
                                month = body.split('..')[3];
                            } else if (body.split('..')[3] != month) throw ("Inconsistent values received from different servers");
                            if (!year) year = body.split('..')[4];
                            else if (body.split('..')[4] != year) throw ("Inconsistent values received from different servers");
                            if (!Provider) Provider = body.split('..')[1];
                            else if (body.split('..')[1] != Provider) throw ("Inconsistent values received by different servers");
                            if (fetch_ethereum !== 'null') {
                                FrTmp = new grp.G2();
                            }
                            pk[Q[i]] = fetch_ethereum === 'null' ? grp.G2.ProjectivePoint.fromHex(body.split('..')[5]) : FrTmp.getStr(body.split('..')[5], 16);
                            if (fetch_ethereum !== 'null') {
                                FrTmp = new grp.G1();
                            }
                            hash[Q[i]] = fetch_ethereum === 'null' ? grp.G1.ProjectivePoint.fromHex(body.split('..')[6]) : FrTmp.getStr(body.split('..')[6], 16);
                            t--;
                            if (t == 0) Finalize(fetch_ethereum, grp);
                        }
                        return;
                    }).catch((err) => {
                        console.error(err.message);
                        process.exit(1);
                    });

                }).catch((err) => {
                    console.error(err.message);
                    process.exit(1);
                });
            } else fetch(Addresses[i] + "/" + provider + "/" + group + "/" + date_path + "/" + options.access_token + "/" + fetch_friends + "/" + fetch_anon + "/" + fetch_ethereum).then(function(response) {
                serverReceipt(i, response, fetch_ethereum === 'null' ? bg : mcl);
            }).catch((err) => {
                console.error(err.message);
                process.exit(1);
            });

        }

    }

    /*
    function ComputeLagrangeCoefficients(lambda, t, Q) {
        const fp = mod.Field(bg.params.r);
        var tmp, I, J;


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
    */
    function ComputeLagrangeCoefficients(lambda, t, Q, fetch_ethereum) {
        const fp = mod.Field(bg.params.r);


        for (let i = 0n; i < t; i++) {
            //tmp = fp.create(1n);
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                FrTmp.setInt(1);
            }
            tmp = fetch_ethereum === 'null' ? fp.create(1n) : FrTmp;
            I = fetch_ethereum === 'null' ? fp.create(Q[i]) : Q[i];
            for (let j = 0n; j < t; j++) {
                J = fetch_ethereum === 'null' ? fp.create(Q[j]) : Q[j];
                if (j == i) continue;

                if (fetch_ethereum !== 'null') {
                    FrTmp = new mcl.Fr();
                    FrTmp2 = new mcl.Fr();
                    FrTmp.setStr((J - I).toString());
                    FrTmp2.setStr(J.toString());
                }
                tmp = fetch_ethereum === 'null' ? fp.mul(fp.div(J, fp.sub(J, I)), tmp) : mcl.mul(mcl.div(FrTmp2, FrTmp), tmp);
            }
            if (fetch_ethereum !== 'null') {
                FrTmp = new mcl.Fr();
                FrTmp.setStr(tmp.getStr());
            }
            lambda[Q[i]] = fetch_ethereum === 'null' ? tmp : FrTmp;

        }
    }

    function Finalize(fetch_ethereum, grp) {
        if ((!options.cross_country && Provider !== provider) || (options.cross_country && provider.split('.')[0] !== Provider)) {
            console.error("Received token shares are for provider " + Provider + " but you requested a token for provider " + provider);
            process.exit(1);
        }
        ComputeLagrangeCoefficients(lambda, options.threshold, Q, fetch_ethereum);
        var tmp = fetch_ethereum === 'null' ? grp.G2.ProjectivePoint.BASE.subtract(grp.G2.ProjectivePoint.BASE) : grp.sub(G2Base, G2Base);
        var tmp2 = fetch_ethereum === 'null' ? grp.G1.ProjectivePoint.BASE.subtract(grp.G1.ProjectivePoint.BASE) : grp.sub(G1Base, G1Base);
        for (let i = 0n; i < options.threshold; i++) {
            pk[Q[i]] = fetch_ethereum === 'null' ? pk[Q[i]].multiply(lambda[Q[i]]) : grp.mul(pk[Q[i]], lambda[Q[i]]);
            hash[Q[i]] = fetch_ethereum === 'null' ? hash[Q[i]].multiply(lambda[Q[i]]) : grp.mul(hash[Q[i]], lambda[Q[i]]);
            tmp = fetch_ethereum === 'null' ? tmp.add(pk[Q[i]]) : grp.add(tmp, pk[Q[i]]);
            tmp2 = fetch_ethereum === 'null' ? tmp2.add(hash[Q[i]]) : grp.add(tmp2, hash[Q[i]]);
        }
        var mpk, token;
        if (fetch_ethereum === 'null') {
            mpk = tmp;
            token = tmp2;
        } else {
            mpk = new grp.G2();
            mpk.setStr(tmp.getStr());
            token = new grp.G1();
            token.setStr(tmp2.getStr());
        }
        if (!options.output_key) console.log("reconstructed master public key: " + (fetch_ethereum === 'null' ? mpk.toHex() : mpk.getStr(16)));
        else {

            console.log("DEBUG: master public key written to file " + options.output_key);
            LogMPK.log((fetch_ethereum === 'null' ? mpk.toHex() : mpk.getStr(16)));
        }
        if (options.cross_country) provider = provider.split('.')[0];
        const id = "LoI.." + provider + ".." + email + ".." + year + ".." + month + ".." + fetch_friends + ".." + fetch_anon + ".." + fetch_ethereum;
        console.log("DEBUG: token is for email: " + email);
        const msg = hashes.utf8ToBytes(id);
        const h = eth.hashToCurve(msg, fetch_ethereum, grp);
        const t1 = grp.pairing(h, mpk);
        const t2 = grp.pairing(token, fetch_ethereum === 'null' ? grp.G2.ProjectivePoint.BASE : G2Base);
        if (fetch_ethereum === 'null' ? (grp.fields.Fp12.eql(t1, t2) == false) : !t1.isEqual(t2)) {
            console.error("Verification of reconstructed token: failure.");
            process.exit(1);
        }
        if (!options.output_token) console.log("reconstructed token: " + (fetch_ethereum === 'null' ? token.toHex() : token.getStr(16)) + " for identity " + id);
        else {
            console.log("DEBUG: token written to file " + options.output_token);
            LogTok.log((fetch_ethereum === 'null' ? token.toHex() : token.getStr(16)));
        }
        console.log("DEBUG: Verification of reconstructed token: success.");

    }

    function OutputJSONFile(t) {
        var obj = {
            Challenges: []
        };
        for (let i = 0; i < options.threshold; i++)
            obj.Challenges.push({
                "Challenge": DIC_Challenge[i]
            });
        const json = JSON.stringify(obj);
        loi_utils.read(fs.createReadStream("./params.json")).then(function(JsonContent) {
            const data = JSON.parse(JsonContent);
            const TIMEOUT_CHALLENGE = data.params.TIMEOUT_CHALLENGE;
            if (options.json) console.log("JSON document written to file " + options.json + ". Sign this file with your own digital identity card to get the file " + options.json + ".p7m " + "and submit it within " + TIMEOUT_CHALLENGE + "secs to LoI with the command:\nnode get_token.js --threshold t -no_nodes n -l list -P dic.it -s " + options.json + ".p7m [OPTIONS]");
            else console.log("Sign the following JSON document with your own digital identity card to get a file file.p7m " + "and submit it within " + TIMEOUT_CHALLENGE + "secs to LoI with the command:\nnode get_token.js -A null --threshold t -no_nodes n -l list -P dic.it -s file.p7m [OPTIONS]\n");
            LogJSON.log(json);
        }).catch((err) => {
            console.error(err.message);
            process.exit(1);
        });
    }

    function serverReceipt(i, response, grp) {
        if (!response.ok) {
            console.error("Server " + Indices[i] + " (" + Addresses[i] + ")" + " response status: " + response.status + ". Try later.");
            process.exit(1);

        } else {
            response.text().then(function(text) {
                console.log("DEBUG: Value received by server " + Indices[i] + " (" + Addresses[i] + "): " + text);
                if (!options.signature && loi_utils.prov_is_dic(provider)) {
                    DIC_Challenge[i] = text;
                    t--;
                    if (t == 0) OutputJSONFile();
                    return;
                }
                if (!email) email = Buffer.from(utils.hexToBytes(text.split('..')[2])).toString('utf8');
                else if (Buffer.from(utils.hexToBytes(text.split('..')[2])).toString('utf8') != email) throw ("Inconsistent values received from different servers");
                if (!month) {
                    month = text.split('..')[4];
                } else if (text.split('..')[4] != month) throw ("Inconsistent values received from different servers or invalid parameters");
                if (!year) year = text.split('..')[3];
                else if (text.split('..')[3] != year) throw ("Inconsistent values received from different servers or invalid parameters");
                if (!Provider) Provider = text.split('..')[1];
                else if (text.split('..')[1] != Provider) throw ("Inconsistent values received by different servers or invalid parameters");
                if (fetch_ethereum !== 'null') {
                    FrTmp = new grp.G2();
                    FrTmp.setStr(text.split('..')[5], 16);
                }
                pk[Q[i]] = fetch_ethereum === 'null' ? grp.G2.ProjectivePoint.fromHex(text.split('..')[5]) : FrTmp;
                if (fetch_ethereum !== 'null') {
                    FrTmp = new grp.G1();
                    FrTmp.setStr(text.split('..')[6], 16);
                }
                hash[Q[i]] = fetch_ethereum === 'null' ? grp.G1.ProjectivePoint.fromHex(text.split('..')[6]) : FrTmp;
                t--;
                if (t == 0) Finalize(fetch_ethereum, grp);
            }).catch(function(err) {
                console.error(err);
            });
        }
    }
} catch (err) {
    console.error(err.message);
    process.exit(1);
}