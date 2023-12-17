function xor(hex1, hex2) {
    const buf1 = Buffer.from(hex1, 'hex');
    const buf2 = Buffer.from(hex2, 'hex');
    const bufResult = buf1.map((b, i) => b ^ buf2[i]);
    return bufResult.toString('hex');
}

function handleProviders(options, provider) {
    if (options.provider && options.provider !== "google" && options.provider !== "facebook" && options.provider !== "google.phone") {
        console.error("Supported providers: google, facebook, google.phone.");
        process.exit(1);
    } else if (!options.provider) provider = "google";
    else provider = options.provider;
    return provider;
}

async function read(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}

module.exports = {
    xor,
    handleProviders,
    read
};
