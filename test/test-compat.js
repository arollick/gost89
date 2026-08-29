var assert = require('assert'),
    compat = require('../lib/compat.js');

var salt = Buffer.from(
    '7b435919fec0c63d1e03f7ac21c8d62a20287a0b0c2d64f2e1bd87b0b9c1b7f7',
    'hex'
);
var iv = Buffer.from(
    '101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F',
    'hex'
);

function kupynaStore() {
    return {
        format: 'PBES2',
        kdf: 'Dstu7564mac-256',
        enc: 'Dstu7624cbc-256',
        container: 'PFX',
        salt: salt,
        iters: 10000,
        iv: iv,
        body: Buffer.from(
            '01e76d4157c059cba0f93473ef402e86e566aca9318f6ebab7f00bafa10d7669',
            'hex'
        ),
        pfxMac: {
            algorithm: 'Dstu7564-256',
            salt: salt,
            iters: 2,
            digest: Buffer.from(
                'f65079ecf1cdfdc801751cace3966a7595665b84aa6e50e7a906ecde36414394',
                'hex'
            ),
            authenticatedSafe: Buffer.from('disposable authenticated safe', 'ascii')
        }
    };
}

function gostMacStore() {
    var store = kupynaStore();
    store.pfxMac = {
        algorithm: 'Gost34311',
        salt: salt,
        iters: 2,
        digest: Buffer.from(
            'f7874a20b743aba0927ed4c43a62f97ede16fc8922b0117d0ea1e2ff75c2f644',
            'hex'
        ),
        authenticatedSafe: Buffer.from('disposable authenticated safe', 'ascii')
    };
    return store;
}

describe('compat stores', function () {
    this.timeout(30000);

    it('derives the Kupyna PBES2 key from the UAPKI vector', function () {
        var key = compat.convert_password(kupynaStore(), '12345');
        assert.equal(
            key.toString('hex'),
            '84c90a0d0e380e4261462b3def89d05fa6fad25697a2bd6dc45e1c749868d9a8'
        );
    });

    it('decrypts and unpads the UAPKI Kupyna/Kalyna profile vector', function () {
        var clear = compat.decode_data(kupynaStore(), '12345');
        assert.equal(clear.toString('ascii'), 'disposable Kupyna PFX vector');
    });

    it('verifies the UAPKI GOST 34.311 outer MAC before Kalyna decryption', function () {
        var store = gostMacStore();
        assert.equal(
            compat.pfx_mac('12345', store.pfxMac).toString('hex'),
            'f7874a20b743aba0927ed4c43a62f97ede16fc8922b0117d0ea1e2ff75c2f644'
        );
        assert.equal(
            compat.decode_data(store, '12345').toString('ascii'),
            'disposable Kupyna PFX vector'
        );

        assert.throws(function () {
            compat.decode_data(gostMacStore(), 'incorrect');
        }, /Invalid PFX password or integrity check/);

        var tampered = gostMacStore();
        tampered.pfxMac.digest = Buffer.from(tampered.pfxMac.digest);
        tampered.pfxMac.digest[0] ^= 1;
        tampered.body = Buffer.alloc(1);
        assert.throws(function () {
            compat.decode_data(tampered, '12345');
        }, /Invalid PFX password or integrity check/);
    });

    it('rejects an incorrect Kupyna/Kalyna profile password', function () {
        assert.throws(function () {
            compat.decode_data(kupynaStore(), 'incorrect');
        }, /Invalid PFX password or integrity check/);
    });

    it('requires authenticated MacData for a Kupyna/Kalyna PFX', function () {
        var store = kupynaStore();
        store.container = 'PFX';
        delete store.pfxMac;
        assert.throws(function () {
            compat.decode_data(store, '12345');
        }, /Authenticated MacData is required/);
    });

    it('does not expose a third-argument PFX authentication bypass', function () {
        var wrongPassword = kupynaStore();
        wrongPassword.container = 'PFX';
        assert.throws(function () {
            compat.decode_data(wrongPassword, 'incorrect', true);
        }, /Invalid PFX password or integrity check/);

        var missingMac = kupynaStore();
        missingMac.container = 'PFX';
        delete missingMac.pfxMac;
        assert.throws(function () {
            compat.decode_data(missingMac, '12345', true);
        }, /Authenticated MacData is required/);
    });

    it('requires MacData when strict-profile provenance fields are omitted', function () {
        var store = kupynaStore();
        delete store.container;
        delete store.pfxMac;
        assert.throws(function () {
            compat.decode_data(store, '12345');
        }, /Authenticated MacData is required/);
        assert.throws(function () {
            compat.decode_stores([store], '12345');
        }, /Authenticated MacData is required/);
    });

    it('rejects inconsistent explicit strict-profile provenance', function () {
        var store = kupynaStore();
        store.container = 'not-PFX';
        assert.throws(function () {
            compat.decode_data(store, '12345');
        }, /Inconsistent Kupyna\/Kalyna PFX provenance/);
    });

    it('accepts 20-byte and 32-byte PBES2 salts', function () {
        var store20 = kupynaStore();
        store20.salt = Buffer.alloc(20, 0x11);
        store20.iters = 1;
        assert.equal(compat.convert_password(store20, '12345').length, 32);
        assert.equal(compat.convert_password(kupynaStore(), '12345').length, 32);
    });

    it('rejects empty and oversized PBES2 salts', function () {
        var empty = kupynaStore();
        empty.salt = Buffer.alloc(0);
        assert.throws(function () {
            compat.convert_password(empty, '12345');
        }, /Invalid PBES2 salt length/);

        var oversized = kupynaStore();
        oversized.salt = Buffer.alloc(compat.MAX_PBES2_SALT_LENGTH + 1);
        assert.throws(function () {
            compat.convert_password(oversized, '12345');
        }, /Invalid PBES2 salt length/);
    });

    it('rejects over-limit PBES2 and PFX MAC iterations before deriving', function () {
        var kdfStore = kupynaStore();
        kdfStore.iters = compat.MAX_KDF_ITERATIONS + 1;
        assert.throws(function () {
            compat.decode_data(kdfStore, '12345');
        }, /Invalid PBES2 iteration count/);

        var macStore = kupynaStore();
        macStore.pfxMac = Object.assign({}, macStore.pfxMac, {
            iters: compat.MAX_KDF_ITERATIONS + 1
        });
        assert.throws(function () {
            compat.decode_data(macStore, '12345');
        }, /Invalid PFX MAC parameters/);
    });

    it('loads multiple stores after one shared PFX MAC verification', function () {
        var first = kupynaStore();
        var second = kupynaStore();
        second.pfxMac = first.pfxMac;
        first.container = 'PFX';
        second.container = 'PFX';
        var clear = compat.decode_stores([first, second], '12345');
        assert.equal(clear.length, 2);
        assert.equal(clear[0].toString('ascii'), 'disposable Kupyna PFX vector');
        assert.equal(clear[1].toString('ascii'), 'disposable Kupyna PFX vector');
    });

    it('rejects too many strict stores without container labels before crypto', function () {
        var first = kupynaStore();
        delete first.container;
        var stores = [];
        for (var i = 0; i <= compat.MAX_PFX_PROTECTED_STORES; i++) {
            var store = kupynaStore();
            delete store.container;
            store.pfxMac = first.pfxMac;
            stores.push(store);
        }
        assert.throws(function () {
            compat.decode_stores(stores, '12345');
        }, /Too many protected stores/);
    });

    it('rejects aggregate PFX KDF work above the supported limit', function () {
        var first = kupynaStore();
        first.container = 'PFX';
        var stores = [first];
        for (var i = 1; i < 3; i++) {
            var store = kupynaStore();
            store.container = 'PFX';
            store.pfxMac = first.pfxMac;
            stores.push(store);
        }
        stores.forEach(function (store) {
            store.iters = compat.MAX_KDF_ITERATIONS;
        });
        assert.throws(function () {
            compat.decode_stores(stores, '12345');
        }, /exceeds total KDF work limit/);
    });

    it('rejects unknown PBES2 profiles', function () {
        var store = kupynaStore();
        store.kdf = 'unknown-kdf';
        assert.throws(function () {
            compat.decode_data(store, '12345');
        }, /Unsupported PBES2 KDF/);
    });

    it('rejects unknown outer PFX MAC algorithms', function () {
        var store = kupynaStore();
        store.pfxMac.algorithm = 'unknown-mac';
        assert.throws(function () {
            compat.decode_data(store, '12345');
        }, /Unsupported PFX MAC algorithm/);
    });

    it('preserves the legacy GOST PBES2 profile', function () {
        var clear = compat.decode_data(
            {
                format: 'PBES2',
                kdf: 'Gost34311-hmac',
                enc: 'Gost28147-cfb',
                salt: Buffer.from(
                    '31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876',
                    'hex'
                ),
                iters: 10000,
                iv: Buffer.from('4bb10f5c2945d49e', 'hex'),
                body: Buffer.from('7546b84a339f22302c5b33e555472ad7df4c3199', 'hex'),
                pfxMac: { algorithm: 'legacy-mac-not-handled-by-this-provider' }
            },
            'password'
        );
        assert.equal(clear.toString('ascii'), 'legacy PBES2 profile');
    });

    it('preserves the IIT profile', function () {
        var clear = compat.decode_data(
            {
                format: 'IIT',
                body: Buffer.from('b7c4460504d729de7938', 'hex'),
                pad: Buffer.from('3a30fa7a7ca4', 'hex')
            },
            'password'
        );
        assert.equal(clear.toString('ascii'), 'legacy IIT');
    });
});

describe('compat hashes', function () {
    it('exposes DSTU 7564-256 for certificate signatures', function () {
        var contents = Buffer.from('DSTU 7564 compatibility', 'utf8');
        var algos = compat.algos();

        assert.equal(
            algos.hashDstu7564(contents).toString('hex'),
            compat.compute_hash_dstu7564(contents).toString('hex')
        );
        assert.equal(algos.hashDstu7564(contents).length, 32);
    });
});
