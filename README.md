# League of Identity - PoC
## Overview
This repository provides a PoC implementation of the ``League of Identity `` (`LoI`)  system described in this [note](https://hackmd.io/noiVZo2dTJ6Wiejt2IJvMg?view). 

``LoI`` is a network of nodes with the following functionality. ``LoI`` publishes what is called a ``master public key`` (``MPK``).
Alice logs into her own Google (or Facebook, Twitter, ...) account `alice@gmail.com` from a given `LoI` website and gets what is called an `OAuth 2` `access token`. Alice can send the so obtained `access token` to a sufficiently large set of nodes of `LoI` requesting to these nodes a cryptographich ``token`` corresponding to her email address and a given month and such set of nodes, upon verifying that the ``access token`` is valid, send back to Alice a set of `token shares` by means of which Alice can compute the (full) `token` corresponding to her email address and the specified month.
Bob can use the `MPK` of `LoI` to encrypt a message associated to `alice@gmail.com` and a given month and can publish the resulting ciphertext on a blockchain or send it directly to Alice. 
Alice can use the previously obtained `token` to decrypt the ciphertext received by Bob and recover the secret message.
We remark that the `token` is different from the `access token`. 

Similarly, the token can be associated to a group. For instance, if Alice belongs to the company `oldcrypto` the token can be associated to the domain `@oldcrypto.com` and anyone can send encrypted messages to all members of such company. Specifically, if for instance `@oldcrypto.com` is a Google Bussiness domain, Alice and Bob, belonging to the company, can log into their Google accounts and get tokens to decrypt ciphertexts associated to `@oldcrypto.com`.

Moreover, the token can be used by Alice to sign transactions over blockchains (e.g. `Cosmos` ones) so that one can form a `Decentralized Autonomous Organization` (`DAO`) based on specific rules.
Consider the following applications scenarios:
* The `DAO` of `@oldcrypto.com` can be created in the obvious way by issuing corresponding `tokens` to users of Gmail accounts with domain `@oldcrypto`.
* `LoI` can issue tokens to the holders of valid digital identity cards (`DIC`) and this would allow to create e.g., a `DAO` of the citizens of a given town. 
* `LoI` can issue tokens corresponding to Instagram accounts with more than 1 million of followers thus creating a `DAO of Influencers`.


## Running a demo
The current demo works only with Google as provider and only performs encryption.

### Install the required packages
The demo has been tested using `node v16.20.2`.
You can switch to such version using the command:
```bash
nvm install 16.20.2
```
For the web part the only required package is `hello.js` but a standalone version is embedded in the `web` folder.
For the `node.js` part the required packages are (some of them could not be currently used) `fetch, express, nocache, cors` and [`noble-curves`](https://github.com/paulmillr/noble-curves).
To install them, run:
```bash
npm install --save express
npm install --save fetch
npm install --save nocache
npm install --save cors
npm install --save @noble-curves@1.2.0
```
Note that for `noble-curves` we stick to the version `1.2.0` we used for the tests. You can try to use newer versions of `node` and `noble-curves` by tweaking the files (e.g., replacing `require` directives with `import` directives). If you have issues with fetch, try to install the version `1.1.0` that we used for the tests.

### Get a Google access token
You first need to run a webserver on the port `5000`, for instance:
```bash
cd web
python3 -m http.server 5000
```

This is because the `main.js` file that implements the webpage embeds a `Google client id` associated with domain `localhost:5000` so changing port will not work with that `client id`. It is strongly suggested that you create a Google developer account and setup your own project and get your own `client id`. Search the line containing the comment ``// client id`` in ``web/main.js`` and replace the corresponding value with your own `client id` .
Then open the link ``localhost:5000`` in your browser, and click on ``Get Access Token``, you should get some view like the following:
<br>
<img src="screenshot1loi.png" width="100%" height="100%" />
<br>

Copy the so obtained ``access token`` in your clipboard. Note that it has a validity of 1hour. We assume henceforth that the variable ``access_token`` contains the text you previously copied to your clipboard.
In this example I computed the token for my email ``vinciovino@gmail.com``.


Observe that in our example we are using a `http` website without `TLS`.
This is only for simplicity. However, be aware that, since we are in the setting of `OAuth implicit flow`, using non-secure connections could make your application insecure.
### Compute the shares and run the `LoI` nodes
Henceforth, we assume to be working in the folder `src`.
`LoI` is associated to two parameters: `n`, the number of nodes in the network, and `t`, the threshold of nodes who can reconstruct the secrets and break the security.
Let us assume henceforth that `t=2` and `n=3`.
Run the following command:

```bash
node compute_shares.js 2 3
```
You will get an output like:
```bash
DEBUG: 1-th coefficient of the 1-degree polynomial: 22616172845692563875646944834802029969319479005231155265423472447676397078828
master secret key: 32d37d4b4f967edd1a92553792ee8decfe9c5f3f49fce4a64e0fdfa4093e43a4
master public key: 98a13c5e305dbad1a006441e59234870103240416f4ec443b930fb6762f80e9254bd78bd3f27ad599df9d522ee724256054221f3bdfe3f3f5233927ec7bd5f585d2f5c7d65bb8efbc36ea8cc24464f65274c40a78cdabda2ec02b5b796d0a2a8
share of the server 1: 64d3ca258dacbeb286faad11268223a5d999ae7cb997798606d69888bcb58cd0
share of the server 2: 22e66faca225813fc0292ce2b073e15960d959b72933b266bf9d516e702cd5fb
share of the server 3: 54e6bc86e03bc1152c9184bc440777123bd6a8f498ce474678640a5323a41f27
reconstructed master public key: 98a13c5e305dbad1a006441e59234870103240416f4ec443b930fb6762f80e9254bd78bd3f27ad599df9d522ee724256054221f3bdfe3f3f5233927ec7bd5f585d2f5c7d65bb8efbc36ea8cc24464f65274c40a78cdabda2ec02b5b796d0a2a8
```
Henceforth we will denote by `share1` (resp. `share2`, `share3`) the so computed `share of the server 1` etc.
So, in the following commands whenever we will write e.g., `share1` you need to replace it with the previous value.

The previous computation simulates the computation of `Distributed Key Generation` (`DKG`) procedure with a trusted dealer.
You can replace it with a real `DKG` procedure without trusted dealer but for simplicity we do not do that.

Now, you can run locally 3 `LoI` nodes with the following commands:
```bash
node loi_server.js 8001 share1 &
node loi_server.js 8002 share2 &
node loi_server.js 8001 share3 &
```
Do not forget to replace `share1`, `share2`, `share3` with the previously computed values. This runs 3 servers on the respective ports `8001`, `8002`, `8003`.
Each server is associated resp. with the index `1,2,3`.
### Get a `token` from `LoI`.
Now you can run the following:
```bash
node get_token.js access_token 2 3 2 http://localhost:8002 3 http://localhost:8003 now 0
```
Do not forget to repalce ``access_token``  with the value computed before (see above).
The first two numerical parameters are the values `t=2,n=3`. Then we use `2 http://localhost:8002` and `3 http://localhost:8003` to denote that we want to request the `token shares` from the nodes with indices `2` and `3`.
If you want to do the request e.g. to the nodes `1,3` you would need to replace the parameters `2 http://localhost:8002 3 http://localhost:8003` with `1 http://localhost:8001 3 http://localhost:8003`.
Here, ``now`` indicates we want a `token` for the current month. Replace it with a string of the form `month.year` to get a `token` for a past month. Moreover, `0` indicates that we do not want a `token` for a group. Replace it with `1` if you want a `token` for a group.

You will get an output like: 
```bash
Value received by server 2 (http://localhost:8002): LoI..google..vinciovino@gmail.com..11..2023..a498c6a0508adbfe812475fbee2da1230fc2068dfd4d07e438ba59f7307cb637b87ff30a3b16a1bc3996c4ac202f2ad304247e020d293fb42f71f5e0c8e14dd5c8a8da925397cba2262453f85b83e3947f6fd3a6c8f937461a728712b4603414..ada3cfb63fd3fe0e45e0537dbeeb62c3a9b8e237a5a92c8a0fc47fc0223c7a7f0d0db5ea588f628a522d79fd8b8b75cc
Value received by server 3 (http://localhost:8003): LoI..google..vinciovino@gmail.com..11..2023..aa653eeeb7ec24a296a67980efd5b069013e3a1df79c879126036e7cf88932d4c32a85088e5a856d618744f2d2e7b42c0e31e25b7581ca10aee77cd0a4d80a039b868e71c730571441d8478b112f317cb79a6a7f06157550c4d7fa559f57681c..a1c5f1131b810fcf76bdc497b2fbf7ffefe3825886e229e85f7f86dc672637a80c8db0e972e8d101035a4e5d74fa80e9
reconstructed master public key: 88b8aa62727da6ab4a10d077a4e5cfe038695925f037db5b7c91efa824d1b7ad80056083077e592f00142ac6abf208d30e4b962b94e2fc8c759a7c6faab7b2f8718b3a8cb156da061176ddeaefb13a6c3568a9614608bddc67f982a1d710d28e
reconstructed token: af5c3a2d675f8750ea1a416c8064c912ccd46e935e16b31a1906532a1ab95646924c31f153a5e030d40118923e9421f5
Verification of reconstructed token: success.
```

Henceforth we will denote by `MPK` the so computed `master public key`.
So, in the following commands whenever we will write e.g., `MPK` you need to replace it with the previous value. Similarly, for the `token`.

### Encrypt
Let us assume that the secret message to encrypt is the string ``aa`` and it is contained in the file `msg`.
Run the following command to encrypt under my email ``vinciovino@gmail.com`` with the tag of ``December 2023``:

```bash
node encrypt.js mpk vinciovino@gmail.com 11.2023 < msg
```
You will get something like:
```bash
ciphertext: 2.afacb96209bc9c9f9e8e1484aee1a42ecd08488f487cc30eac89bee7ebffb3327040e3bcf77c9378e646ec118fb9ba2004b734a0502f3c3df658660041659a5582ce9e662ccfefb68dd2a421227676a79b529a11d1c474526c253ff57cb15a82.6b5d
```
Henceforth, let us assume that the previous ciphertext is contained in the variable ``ciphertext``.

Note that in order to encrypt for `December` we used `11.2023` not `12.2023`. This is because the `month` field starts from `0`, that is it is an integer between `0` and `11`.

### Decrypt
Now, you can decrypt with the following command:
```bash
node decrypt.js token mpk vinciovino@gmail.com 11.2023 ciphertext
Verification of token: success.
aa
```
You should get in the end the recovered message contained in the file ``msg``.

### Group encryption/decryption
For group encryption/decryption just specify the domain (e.g., `@oldcrypto.com`) instead of a full email. Also, recall that you need a `token` for groups (see above).
## TODOs
* Add signatures as described in the original paper.
* Implement CCA2-secure encryption.
* Additional providers with social features (e.g., tokens for Instagram/Twitter users with at least `X` followers).
* Digital identity cards.
## References
Vincenzo Iovino, Aragon ZK Research. [League of Identity: distributed identity-based encryption and authentication from Google and other providers](https://hackmd.io/noiVZo2dTJ6Wiejt2IJvMg?view), 2023.
