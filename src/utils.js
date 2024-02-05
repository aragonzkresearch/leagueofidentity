function xor(hex1, hex2) {
    const buf1 = Buffer.from(hex1, 'hex');
    const buf2 = Buffer.from(hex2, 'hex');
    const bufResult = buf1.map((b, i) => b ^ buf2[i]);
    return bufResult.toString('hex');
}

function handleProviders(options, provider) {
    if (options.provider && options.provider !== "google" && options.provider !== "facebook" && options.provider !== "google.phone" && options.provider !== 'dic.it' && options.provider !== 'eth' && options.provider !== 'nintendo') {
        console.error("Supported providers: google, facebook, google.phone, eth, dic.it, nintendo.");
        process.exit(1);
    } else if (!options.provider) provider = "google";
    else provider = options.provider;
    return provider;
}

function handleOptionFriends(options, provider) {
    var opts;
    if ((provider === "facebook" || provider === "eth") && options.friends) opts = options.friends;
    else opts = "null";
    return opts;
}

function handleOptionAnon(options, provider) {
    var opts;
    if (provider !== "nintendo" && provider !== "google.phone" && options.anonymous) opts = "1";
    else opts = "0";
    return opts;
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

function pad(s) {
    var n = 64 - s.length;
    for (let i = 0; i < n; i++) s = "0" + s;
    return s;
}

function padOdd(s) {
    if (s.length % 2 === 1) return "0" + s;
}

function handleDate(reqDate) {
    var y, m, curyear, curmnonth;
    const date = new Date();
    curyear = date.getFullYear();
    curmonth = date.getMonth();
    if (reqDate !== "now") {
        y = reqDate.split('.')[1];
        m = reqDate.split('.')[0];
        if (isNaN(parseInt(y)) || isNaN(parseInt(m)) || y < 0 || m < 0 || m > 11 || y < 2023) return "null";
        m = m - 1; // we remove trailings 0s or + symbols. for example if m is "01" after this sequence of two instructions m will be "1".
        m = m + 1;
        y = y - 1;
        y = y + 1;
        if (y > curyear || (y == curyear && m > curmonth)) return "null";
        return {
            year: y,
            month: m
        };
    } else return {
        year: curyear,
        month: curmonth
    };
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
    pad,
    padOdd,
    handleDate,
};