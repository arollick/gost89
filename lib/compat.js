'use strict';

var Buffer = require('buffer').Buffer;

var keywrap = require('./keywrap.js'),
    util = require('./util.js'),
    Gost = require('./gost89.js'),
    Hash = require('./hash.js'),
    dstu = require('./dstu.js'),
    dstu7564 = require('dstu7564'),
    dstu7624 = require('dstu7624');

var MAX_PBES2_SALT_LENGTH = 1024;
var MAX_KDF_ITERATIONS = 100000;
var MAX_PFX_PROTECTED_STORES = 16;
var MAX_PFX_TOTAL_KDF_ITERATIONS = 300000;

var pbes2_profile = function (parsed) {
    if (!parsed.kdf && !parsed.enc) {
        return {
            kdf: 'Gost34311-hmac',
            enc: 'Gost28147-cfb'
        };
    }
    if (!parsed.kdf || !parsed.enc) {
        throw new Error('Incomplete PBES2 profile');
    }
    return {
        kdf: parsed.kdf,
        enc: parsed.enc
    };
};

var is_kupyna_pfx_profile = function (profile) {
    return profile.kdf === 'Dstu7564mac-256' &&
        profile.enc === 'Dstu7624cbc-256';
};

var validate_pbes2_params = function (parsed) {
    if (!Buffer.isBuffer(parsed.salt) || parsed.salt.length === 0 ||
            parsed.salt.length > MAX_PBES2_SALT_LENGTH) {
        throw new Error('Invalid PBES2 salt length');
    }
    if (!Number.isSafeInteger(parsed.iters) || parsed.iters < 1 ||
            parsed.iters > MAX_KDF_ITERATIONS) {
        throw new Error('Invalid PBES2 iteration count');
    }
};

var kupyna_kdf = function (pw, salt, iters) {
    var raw = Buffer.from(pw);
    var password = Buffer.alloc(32);
    raw.copy(password, 0, 0, 32);

    var counter = Buffer.from([0, 0, 0, 1]);
    var kmac = dstu7564.dstu7564_kmac(password, 32);
    var u = kmac.compute(Buffer.concat([salt, counter]));
    var result = Buffer.from(u);

    for (var j = 1; j < iters; j++) {
        u = kmac.compute(u);
        for (var i = 0; i < result.length; i++) {
            result[i] ^= u[i];
        }
    }
    return result;
};

var pkcs7_unpad = function (buf, block_size) {
    if (buf.length === 0 || buf.length % block_size !== 0) {
        throw new Error('Invalid password or corrupted PBES2 data');
    }

    var pad = buf[buf.length - 1];
    var invalid = pad === 0 || pad > block_size;
    for (var i = 1; i <= block_size; i++) {
        if (i <= pad && buf[buf.length - i] !== pad) {
            invalid = true;
        }
    }
    if (invalid) {
        throw new Error('Invalid password or corrupted PBES2 data');
    }
    return buf.slice(0, buf.length - pad);
};

var pfx_mac_profile = function (algorithm) {
    if (algorithm === 'Dstu7564-256') {
        return {
            block_size: 64,
            hash: function (data) {
                return dstu7564.computeHash(32, data);
            }
        };
    }
    if (algorithm === 'Gost34311') {
        return {
            block_size: 32,
            hash: Hash.gosthash
        };
    }
    throw new Error('Unsupported PFX MAC algorithm: ' + algorithm);
};

var pfx_mac_key = function (pw, mac) {
    var profile = pfx_mac_profile(mac.algorithm);
    var salt = mac.salt;
    var iters = mac.iters;

    var password = Buffer.from(Buffer.isBuffer(pw) ? pw.toString('utf8') : String(pw), 'utf16le');
    password.swap16();
    password = Buffer.concat([password, Buffer.alloc(2)]);

    var block_size = profile.block_size;
    var repeated_salt = Buffer.alloc(block_size * Math.ceil(salt.length / block_size));
    var repeated_password = Buffer.alloc(block_size * Math.ceil(password.length / block_size));
    for (var i = 0; i < repeated_salt.length; i++) {
        repeated_salt[i] = salt[i % salt.length];
    }
    for (var j = 0; j < repeated_password.length; j++) {
        repeated_password[j] = password[j % password.length];
    }

    var diversifier = Buffer.alloc(block_size, 3);
    var key = profile.hash(Buffer.concat([diversifier, repeated_salt, repeated_password]));
    for (var round = 1; round < iters; round++) {
        key = profile.hash(key);
    }
    return key;
};

var gost_hmac = function (key, message) {
    var ipad = Buffer.alloc(32, 0x36);
    var opad = Buffer.alloc(32, 0x5c);
    for (var i = 0; i < key.length; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    return Hash.gosthash(Buffer.concat([
        opad,
        Hash.gosthash(Buffer.concat([ipad, message]))
    ]));
};

var pfx_mac = function (pw, mac) {
    if (!mac || !Buffer.isBuffer(mac.authenticatedSafe)) {
        throw new Error('Invalid PFX MAC parameters');
    }
    validate_pfx_mac_params(mac);
    var key = pfx_mac_key(pw, mac);
    if (mac.algorithm === 'Dstu7564-256') {
        return dstu7564.dstu7564_kmac(key, 32).compute(mac.authenticatedSafe);
    }
    return gost_hmac(key, mac.authenticatedSafe);
};

var validate_pfx_mac_params = function (mac) {
    if (!mac || !Buffer.isBuffer(mac.salt) || mac.salt.length === 0 ||
            mac.salt.length > MAX_PBES2_SALT_LENGTH ||
            !Number.isSafeInteger(mac.iters) || mac.iters < 1 ||
            mac.iters > MAX_KDF_ITERATIONS) {
        throw new Error('Invalid PFX MAC parameters');
    }
    pfx_mac_profile(mac.algorithm);
};

var verify_pfx_mac = function (parsed, pw) {
    var mac = parsed.pfxMac;
    if (!mac) {
        throw new Error('Authenticated MacData is required for Kupyna/Kalyna PFX');
    }
    if (parsed.container !== undefined && parsed.container !== 'PFX') {
        throw new Error('Inconsistent Kupyna/Kalyna PFX provenance');
    }
    if (!Buffer.isBuffer(mac.digest) || mac.digest.length !== 32 ||
            !Buffer.isBuffer(mac.authenticatedSafe)) {
        throw new Error('Invalid PFX MAC parameters');
    }

    var actual = pfx_mac(pw, mac);
    var different = 0;
    for (var i = 0; i < actual.length; i++) {
        different |= actual[i] ^ mac.digest[i];
    }
    if (different !== 0) {
        throw new Error('Invalid PFX password or integrity check');
    }
};

var convert_password = function (parsed, pw) {
    if (parsed.format === 'IIT') {
        return util.dumb_kdf(pw, 10000);
    }
    if (parsed.format === 'PBES2') {
        validate_pbes2_params(parsed);
        var profile = pbes2_profile(parsed);
        if (profile.kdf === 'Gost34311-hmac') {
            return util.pbkdf(pw, parsed.salt, parsed.iters);
        }
        if (profile.kdf === 'Dstu7564mac-256') {
            return kupyna_kdf(pw, parsed.salt, parsed.iters);
        }
        throw new Error('Unsupported PBES2 KDF: ' + profile.kdf);
    }

    throw new Error("Failed to convert key");
};

var decode_data_unchecked = function (parsed, pw) {
    var bkey;

    var ctx = Gost.init();
    var buf, obuf;
    if (parsed.format === 'PBES2') {
        validate_pbes2_params(parsed);
        var store_profile = pbes2_profile(parsed);
        if (is_kupyna_pfx_profile(store_profile)) {
            if (!Buffer.isBuffer(parsed.iv) || parsed.iv.length !== 32 ||
                    !Buffer.isBuffer(parsed.body) || parsed.body.length === 0 ||
                    parsed.body.length % 32 !== 0) {
                throw new Error('Invalid Dstu7564mac-256/Dstu7624cbc-256 parameters');
            }
        }
    }
    bkey = convert_password(parsed, pw, true);
    ctx.key(bkey);

    if (parsed.format === 'IIT') {
        buf = Buffer.concat([parsed.body, parsed.pad]);
        obuf = Buffer.alloc(buf.length);
        ctx.decrypt(buf, obuf);
        return obuf.slice(0, parsed.body.length);
    }
    if (parsed.format === 'PBES2') {
        var profile = pbes2_profile(parsed);
        if (is_kupyna_pfx_profile(profile)) {
            buf = dstu7624.cbcDecrypt(bkey, parsed.iv, parsed.body);
            return pkcs7_unpad(buf, 32);
        }
        if (profile.kdf !== 'Gost34311-hmac' || profile.enc !== 'Gost28147-cfb') {
            throw new Error('Unsupported PBES2 profile: ' + profile.kdf + '/' + profile.enc);
        }
        buf = parsed.body;
        obuf = Buffer.alloc(buf.length);
        ctx.decrypt_cfb(parsed.iv, buf, obuf);
        return obuf;
    }
};

var decode_data = function (parsed, pw) {
    if (parsed.format === 'PBES2') {
        var profile = pbes2_profile(parsed);
        if (is_kupyna_pfx_profile(profile)) {
            verify_pfx_mac(parsed, pw);
        }
    }
    return decode_data_unchecked(parsed, pw);
};

var validate_pfx_budget = function (stores) {
    var protected_stores = [];
    var macs = [];
    stores.forEach(function (parsed) {
        if (parsed.format !== 'PBES2') {
            return;
        }
        var profile = pbes2_profile(parsed);
        if (!is_kupyna_pfx_profile(profile)) {
            return;
        }
        if (!parsed.pfxMac) {
            throw new Error('Authenticated MacData is required for Kupyna/Kalyna PFX');
        }
        if (parsed.container !== undefined && parsed.container !== 'PFX') {
            throw new Error('Inconsistent Kupyna/Kalyna PFX provenance');
        }
        validate_pfx_mac_params(parsed.pfxMac);
        protected_stores.push(parsed);
        if (macs.indexOf(parsed.pfxMac) === -1) {
            macs.push(parsed.pfxMac);
        }
    });

    if (protected_stores.length > MAX_PFX_PROTECTED_STORES) {
        throw new Error('Too many protected stores in Kupyna/Kalyna PFX');
    }
    var total = protected_stores.reduce(function (sum, parsed) {
        return sum + parsed.iters;
    }, 0);
    total = macs.reduce(function (sum, mac) {
        return sum + mac.iters;
    }, total);
    if (total > MAX_PFX_TOTAL_KDF_ITERATIONS) {
        throw new Error('Kupyna/Kalyna PFX exceeds total KDF work limit');
    }
};

var decode_stores = function (stores, pw) {
    var verified = [];
    stores.forEach(function (parsed) {
        if (parsed.format !== 'PBES2') {
            return;
        }
        validate_pbes2_params(parsed);
        var profile = pbes2_profile(parsed);
        if (is_kupyna_pfx_profile(profile) &&
                (!Buffer.isBuffer(parsed.iv) || parsed.iv.length !== 32 ||
                !Buffer.isBuffer(parsed.body) || parsed.body.length === 0 ||
                parsed.body.length % 32 !== 0)) {
            throw new Error('Invalid Dstu7564mac-256/Dstu7624cbc-256 parameters');
        }
    });
    validate_pfx_budget(stores);
    stores.forEach(function (parsed) {
        if (parsed.format !== 'PBES2') {
            return;
        }
        var profile = pbes2_profile(parsed);
        if (!is_kupyna_pfx_profile(profile)) {
            return;
        }
        if (!parsed.pfxMac || verified.indexOf(parsed.pfxMac) === -1) {
            verify_pfx_mac(parsed, pw);
            if (parsed.pfxMac) {
                verified.push(parsed.pfxMac);
            }
        }
    });
    return stores.map(function (parsed) {
        return decode_data_unchecked(parsed, pw);
    });
};

var encode_data = function (raw, format, pw, iv, salt) {
    const ctx = Gost.init();
    if (format === 'PBES2') {
        const iters = 10000;
        const sbox = dstu.packSbox(dstu.defaultSbox);
        const bkey = convert_password({iters, salt, format}, pw, true);
        ctx.key(bkey);
        const obuf = Buffer.alloc(raw.length);
        ctx.crypt_cfb(iv, raw, obuf);
        return {format, iv, salt, iters, body: obuf, sbox};
    }
};

var compute_hash = function (contents) {
    return Hash.gosthash(contents);
};

var gost_unwrap = function (kek, inp) {
    return keywrap.unwrap(inp, kek);
};

var gost_keywrap = function (kek, inp, iv) {
    return keywrap.wrap(inp, kek, iv);
};

var gost_kdf = function (buffer) {
    return compute_hash(buffer);
};

var gost_crypt = function (mode, inp, key, iv) {
    var ctx = Gost.init();
    ctx.key(key);
    if (mode) {
        return ctx.decrypt_cfb(iv, inp);
    } else {
        return ctx.crypt_cfb(iv, inp);
    }
};

var gost_decrypt_cfb = function(cypher, key, iv) {
    return gost_crypt(1, cypher, key, iv);
};

var gost_encrypt_cfb = function(cypher, key, iv) {
    return gost_crypt(0, cypher, key, iv);
};

module.exports.decode_data = decode_data;
module.exports.decode_stores = decode_stores;
module.exports.convert_password = convert_password;
module.exports.pfx_mac = pfx_mac;
module.exports.MAX_PBES2_SALT_LENGTH = MAX_PBES2_SALT_LENGTH;
module.exports.MAX_KDF_ITERATIONS = MAX_KDF_ITERATIONS;
module.exports.MAX_PFX_PROTECTED_STORES = MAX_PFX_PROTECTED_STORES;
module.exports.MAX_PFX_TOTAL_KDF_ITERATIONS = MAX_PFX_TOTAL_KDF_ITERATIONS;
module.exports.compute_hash = compute_hash;
module.exports.gost_kdf = gost_kdf;
module.exports.gost_unwrap = gost_unwrap;
module.exports.gost_keywrap = gost_keywrap;
module.exports.gost_decrypt_cfb = gost_decrypt_cfb;
module.exports.gost_encrypt_cfb = gost_encrypt_cfb;
module.exports.algos = function () {
    return {
        kdf: gost_kdf,
        keywrap: gost_keywrap,
        keyunwrap: gost_unwrap,
        encrypt: gost_encrypt_cfb,
        decrypt: gost_decrypt_cfb,
        hash: compute_hash,
        storeload: decode_data,
        storeloadall: decode_stores,
        storesave: encode_data,
    };
};
