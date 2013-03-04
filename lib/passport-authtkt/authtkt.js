/**
 * JavaScript implementation of the mod_auth_tkt cookie standard.
 *
 * Ported from https://github.com/plone/plone.session/blob/master/plone/session/tktauth.py
 */

var crypto  = require('crypto');
var _       = require('underscore');
var sprintf = require('sprintf').sprintf;
var jspack  = require('jspack').jspack;

// Pack a dotted quad IP address into an octet array
exports.inet_aton = function(ip) {
    return _.reduce(ip.split('.'), function(memo, num) {
        return memo.concat(jspack.Pack("!B", [parseInt(num, 10)]));
    }, []);
};

// Pack a numeric timestamp into an octet array
exports.packTimestamp = function(timestamp) {
    return jspack.Pack("!I", [timestamp]);
};

// Constant time comparison; avoid potential attack vector
exports.isEqual = function(val1, val2) {
    if(typeof val1 != "string" || typeof val2 != "string")
        return false;

    if(val1.length != val2.length)
        return false;

    var result = 0;
    _.each(_.zip(val1, val2), function(pair) {
        result |= pair[0].charCodeAt(0) ^ pair[1].charCodeAt(0);
    });

    return result === 0;
};

// Create a mod_auth_tkt digest
exports.createDigest = function(secret, data1, data2) {
    var digest0 = crypto.createHash('md5').update(Buffer.concat([new Buffer(data1), new Buffer(secret), new Buffer(data2)])).digest('hex');
    var digest = crypto.createHash('md5').update(digest0 + secret).digest('hex');
    return digest;
};

// Create a mod_auth_tkt ticket
exports.createTicket = function(secret, userid, tokens, userData, timestamp, ip) {

    if(!tokens) tokens = [];
    if(!userData) userData = '';
    if(!timestamp) timestamp = null;
    if(!ip) ip = '0.0.0.0';

    if(!timestamp)
        timestamp = Math.round(new Date().getTime() / 1000);

    var tokenList = tokens.join(",");

    var data1 = exports.inet_aton(ip).concat(exports.packTimestamp(timestamp));
    var data2 = userid + '\0' + tokenList + '\0' + userData;
    var digest = exports.createDigest(secret, data1, data2);

    // digest + timestamp as an eight character hexadecimal + userid + !
    var ticket = sprintf("%s%08x%s!", digest, timestamp, userid);

    if(tokens.length > 0)
        ticket += tokenList + '!';
    ticket += userData;

    return ticket;
};

// Parse a ticket into an object
exports.splitTicket = function(ticket) {
    var digest    = ticket.slice(0, 32),
        val       = ticket.slice(32, 40),
        remainder = ticket.slice(40),
        parts, timestamp, userid, userData, tokens;

    if(!val)
        throw Error("No value in ticket string");

    timestamp = parseInt(val, 16); // convert from hexadecimal

    parts = remainder.split("!");
    if(parts.length == 2) {
        userid = parts[0];
        userData = parts[1];
        tokens = [];
    } else if(parts.length == 3) {
        userid = parts[0];
        userData = parts[2];
        tokens = parts[1].split(',');
    } else {
        throw Error("Invalid remainder in ticket");
    }

    return {
        digest: digest,
        userid: userid,
        tokens: tokens,
        userData: userData,
        timestamp: timestamp
    };
};

// Validate a ticket, returning either its data or null
exports.validateTicket = function(secret, ticket, timeout, ip, now) {
    var data, newTicket;

    if(!now) now = new Date().getTime() / 1000;
    if(!ip) ip = '0.0.0.0';

    try {
        data = exports.splitTicket(ticket);
    } catch(e) {
        console.error("Invalid auth tkt: " + e);
        return null;
    }

    newTicket = exports.createTicket(secret, data.userid, data.tokens, data.userData, data.timestamp, ip);
    if(exports.isEqual(newTicket.slice(0, 32), data.digest)) {
        if(!timeout)
            return data;
        if(data.timestamp + timeout > now)
            return data;
    }

    return null;
};

// Convert to/from base64 cookie values
exports.toBase64 = function(tkt) {
    return new Buffer(tkt).toString('base64').trim();
};
exports.fromBase64 = function(val) {
    return new Buffer(val, 'base64').toString('ascii');
};