var vows = require('vows');
var assert = require('assert');
var util = require('util');
var AuthTkt = require('passport-authtkt').AuthTkt;

vows.describe("AuthTkt").addBatch({

    'ticket management': {
        topic: new AuthTkt('abcdefghijklmnopqrstuvwxyz0123456789'),

        "supports constant-time comparison for strings": function(authtkt) {
            assert.isTrue(authtkt.isEqual("a", "a"));
            assert.isTrue(authtkt.isEqual("alpha", "alpha"));

            assert.isFalse(authtkt.isEqual("alpha", "beta"));
            assert.isFalse(authtkt.isEqual("123", "321"));

            assert.isFalse(authtkt.isEqual(null, null));
            assert.isFalse(authtkt.isEqual(1, 1));

        },

        "creates mod_auth_tkt double digests": function(authtkt) {
            assert.equal(authtkt.createDigest("secret", "data1", "data2"), "45409cbaf692d8213a128b703edd5ce2");
        },

        "provides an inet_aton algorithm to pack dotted quads into four bytes": function(authtkt) {
            assert.deepEqual(authtkt.inetAton("0.0.0.0"), [0, 0, 0, 0]);
            assert.deepEqual(authtkt.inetAton("192.168.0.10"), [192, 168, 0, 10]);
        },

        "can split tickets for parsing": function(authtkt) {
            var tkt = 'c7c7300ac5cf529656444123aca345294885afa0jbloggs!';
            assert.deepEqual(authtkt.splitTicket(tkt), {
                digest: 'c7c7300ac5cf529656444123aca34529',
                userid: 'jbloggs',
                tokens: [],
                userData: '',
                timestamp: 1216720800
            });

        },

        "can create valid tickets": function(authtkt) {
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var tkt = authtkt.createTicket(userid, {timestamp: timestamp});

            assert.equal(tkt, 'c7c7300ac5cf529656444123aca345294885afa0jbloggs!');
        },

        "can encode and decode base64": function(authtkt) {
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var tkt = authtkt.createTicket(userid, {timestamp: timestamp});

            var b64 = authtkt.base64Encode(tkt);
            assert.equal(b64, 'YzdjNzMwMGFjNWNmNTI5NjU2NDQ0MTIzYWNhMzQ1Mjk0ODg1YWZhMGpibG9nZ3Mh');

            reversed = authtkt.base64Decode(b64);
            assert.equal(reversed, 'c7c7300ac5cf529656444123aca345294885afa0jbloggs!');
        },

        "can validate tickets": function(authtkt) {
            var timeout = 12*60*60;
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var tkt = 'c7c7300ac5cf529656444123aca345294885afa0jbloggs!';
            var now, data;

            // An hour after creation
            now = timestamp + 60*60;
            data = authtkt.validateTicket(tkt, {timeout: timeout, now: now});
            assert.isNotNull(data);

            // After the timeout
            now += timeout;
            data = authtkt.validateTicket(tkt, {timeout: timeout, now: now});
            assert.isNull(data);
        },

        "can store user data and tokens": function(authtkt) {
            var timeout = 12*60*60;
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var now = timestamp + 60*60;
            var userData = 'Joe Bloggs';
            var tokens = ['foo', 'bar'];

            var tkt = authtkt.createTicket(userid, {
                tokens: tokens,
                userData: userData,
                timestamp: timestamp,
                encodeUserData: false
            });
            assert.equal(tkt, 'eea3630e98177bdbf0e7f803e1632b7e4885afa0jbloggs!foo,bar!Joe Bloggs');

            var data = authtkt.validateTicket(tkt, {timeout: timeout, now: now, encodeUserData: false});

            assert.deepEqual(data, {
                digest: 'eea3630e98177bdbf0e7f803e1632b7e',
                userid: 'jbloggs',
                tokens: ['foo', 'bar'],
                userData: 'Joe Bloggs',
                timestamp: 1216720800
            });
        },

        "stores user data base64 encoded by default": function(authtkt) {
            var timeout = 12*60*60;
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var now = timestamp + 60*60;
            var userData = 'Joe Bloggs';
            var tokens = ['foo', 'bar'];

            var tkt = authtkt.createTicket(userid, {
                tokens: tokens,
                userData: userData,
                timestamp: timestamp
            });
            assert.equal(tkt, 'eea3630e98177bdbf0e7f803e1632b7e4885afa0jbloggs!foo,bar!Sm9lIEJsb2dncw==');

            var data = authtkt.validateTicket(tkt, {timeout: timeout, now: now});

            assert.deepEqual(data, {
                digest: 'eea3630e98177bdbf0e7f803e1632b7e',
                userid: 'jbloggs',
                tokens: ['foo', 'bar'],
                userData: 'Joe Bloggs',
                timestamp: 1216720800
            });
        },

        "can create valid encoded cookies": function(authtkt) {
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var tkt = authtkt.getCookie(userid, {timestamp: timestamp});

            assert.equal(tkt, 'YzdjNzMwMGFjNWNmNTI5NjU2NDQ0MTIzYWNhMzQ1Mjk0ODg1YWZhMGpibG9nZ3Mh');
        },

        "can parse valid encoded cookies": function(authtkt) {
            var timeout = 12*60*60;
            var userid = 'jbloggs';
            var timestamp = 1216720800;
            var cookie = 'YzdjNzMwMGFjNWNmNTI5NjU2NDQ0MTIzYWNhMzQ1Mjk0ODg1YWZhMGpibG9nZ3Mh';
            var now, data;

            // An hour after creation
            now = timestamp + 60*60;
            data = authtkt.validateCookie(cookie, {timeout: timeout, now: now});

            assert.deepEqual(data, {
                digest: 'c7c7300ac5cf529656444123aca34529',
                userid: 'jbloggs',
                tokens: [],
                userData: '',
                timestamp: 1216720800
            });
        }
    }

}).export(module);