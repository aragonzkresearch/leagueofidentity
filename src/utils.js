function xor(hex1, hex2) {
    const buf1 = Buffer.from(hex1, 'hex');
    const buf2 = Buffer.from(hex2, 'hex');
    const bufResult = buf1.map((b, i) => b ^ buf2[i]);
    return bufResult.toString('hex');
}

function handleProviders(options, provider) {
    if (options.provider && options.provider !== "google" && options.provider !== "facebook" && options.provider !== "google.phone" && options.provider !== 'dic.it') {
        console.error("Supported providers: google, facebook, google.phone, dic.it.");
        process.exit(1);
    } else if (!options.provider) provider = "google";
    else provider = options.provider;
    return provider;
}

function handleOptionFriends(options, provider) {
    var opts;
    if (provider === "facebook" && options.friends) opts = options.friends;
    else opts = "null";
    return opts;
}

function handleOptionAnon(options, provider) {
    var opts;
    if (provider !== "google.phone" && options.anonymous) opts = "1";
    else opts = "0";
    return opts;
}

async function read(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}
async function read(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}

function prov_is_dic(provider) {
    if (provider.split('.')[0] === 'dic' && provider.split('.')[1] === 'it') return true;
    else return false;
}

function dic_country(provider) {
    return provider.split('.')[1];
}

function getMonth(options) {
    if (options.month) return options.month.split('.')[0];
    const date = new Date();
    return date.getMonth();
}

function getYear(options) {
    if (options.month) return options.month.split('.')[1];
    const date = new Date();
    return date.getFullYear();
}

module.exports = {
    xor,
    handleProviders,
    handleOptionFriends,
    handleOptionAnon,
    getMonth,
    getYear,
    read,
    prov_is_dic,
    dic_country,
};