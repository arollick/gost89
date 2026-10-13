'use strict';

var assert = require('assert');
var kupyna = require('../dstu7564');
var compat = require('../lib/compat');

describe('bundled Uint32 Kupyna', function () {
    it('matches the empty-message 256-bit and 512-bit vectors', function () {
        assert.equal(kupyna.computeHash(32, Buffer.alloc(0)).toString('hex'),
            'cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6');
        assert.equal(kupyna.computeHash(64, Buffer.alloc(0)).toString('hex'),
            '656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538');
    });

    it('matches the KMAC vector on repeated keyed computations', function () {
        var key = Buffer.from('707172737475767778797a7b7c7d7e7f80818283', 'hex');
        var data = Buffer.from('Hello World');
        var expected = 'ac9b3027afaa041cb623b098d51200801432290afa30311d11b2450f3d95d98a';
        var kmac = kupyna.dstu7564_kmac(key, 32);
        assert.equal(kupyna.computeKmac(key, data, 32).toString('hex'), expected);
        assert.equal(kmac.compute(data).toString('hex'), expected);
        assert.equal(kmac.compute(data).toString('hex'), expected);
    });

    it('is used by the compatibility provider without a separate package', function () {
        var original = kupyna.computeHash;
        var calls = 0;
        kupyna.computeHash = function (size, data) {
            calls++;
            return original(size, data);
        };
        try {
            assert.deepEqual(compat.compute_hash_dstu7564(Buffer.alloc(0)), original(32, Buffer.alloc(0)));
            assert.equal(calls, 1);
        } finally {
            kupyna.computeHash = original;
        }
    });
});
