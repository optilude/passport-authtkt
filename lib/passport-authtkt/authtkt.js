/**
 * JavaScript implementation of the mod_auth_tkt cookie standard.
 *
 * Ported from https://github.com/plone/plone.session/blob/master/plone/session/tktauth.py
 */

var crypto  = require('crypto');
var sprintf = require('sprintf').sprintf;
var jspack  = require('jspack').jspack;

/**
 * Create a new AuthTkt utility.
 *
 * @param {String} secret The secret to use for ticket creation/validation
 * @param {Object} options
 *
 * Valid options include:
 *
 *   - `encodeUserData`    Encode and decode the userData string using base64.
 *                         Defaults to true.
 *   - `jsonUserData`      Encode and decode the userData string as JSON.
 *                         Defaults to false.
 *   - `ip`                Use the given IP address (a dotted quad string)
 *                         to create/validate tickets.
 *   - `timeout`           Time, in seconds, for ticket validation.
 *
 * Options can also be overridden when passed to individual methods.
 */
var AuthTkt = function(secret, options) {
    this.secret = secret;
    this.options = options || {};
};

/**
 * Create a mod_auth_tkt ticket
 *
 * @param {String} userid User id to encode
 * @param {Object} options can contain `tokens`, `userData`, `timestamp`, and 'ip'
 * @return {String}
 */
AuthTkt.prototype.createTicket = function(userid, options) {
    options = options || {};
    var secret = this.secret,
        tokens = options.tokens || this.options.tokens || [],
        userData = options.userData || this.options.userData || '',
        timestamp = options.timestamp || this.options.timestamp || Math.round(new Date().getTime() / 1000),
        ip = options.ip || this.options.ip || '0.0.0.0',
        encodeUserData = true,
        jsonUserData = false;

    if(options.encodeUserData !== undefined) encodeUserData = options.encodeUserData;
    else if(this.options.encodeUserData !== undefined) encodeUserData = this.options.encodeUserData;

    if(options.jsonUserData !== undefined) jsonUserData = options.jsonUserData;
    else if(this.options.jsonUserData !== undefined) jsonUserData = this.options.jsonUserData;

    var tokenList = tokens.join(",");

    if(jsonUserData)
        userData = JSON.stringify(userData);

    var data1 = this.inetAton(ip).concat(this.packTimestamp(timestamp)),
        data2 = userid + '\0' + tokenList + '\0' + userData;
        digest = this.createDigest(secret, data1, data2);

    // digest + timestamp as an eight character hexadecimal + userid + !
    var ticket = sprintf("%s%08x%s!", digest, timestamp, userid);

    if(tokens.length > 0)
        ticket += tokenList + '!';
    ticket += encodeUserData? this.base64Encode(userData) : userData;

    return ticket;
};

/**
 * Parse a ticket into an object with keys `userid`, `tokens`, `userData`
 * and `timestamp`.
 *
 * @param {String} ticket The ticket to parse
 * @param {Object} options including `encodeUserData` and `jsonUserData`
 * @return {Object}
 */
AuthTkt.prototype.splitTicket = function(ticket, options) {
    options = options || {};
    var digest    = ticket.slice(0, 32),
        val       = ticket.slice(32, 40),
        remainder = ticket.slice(40),
        encodeUserData = true,
        jsonUserData   = false,
        parts, timestamp, userid, userData, tokens;

    if(options.encodeUserData !== undefined) encodeUserData = options.encodeUserData;
    else if(this.options.encodeUserData !== undefined) encodeUserData = this.options.encodeUserData;

    if(options.jsonUserData !== undefined) jsonUserData = options.jsonUserData;
    else if(this.options.jsonUserData !== undefined) jsonUserData = this.options.jsonUserData;

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

    if(encodeUserData)
        userData = this.base64Decode(userData);
    if(jsonUserData)
        userData = JSON.parse(userData);

    return {
        digest: digest,
        userid: userid,
        tokens: tokens,
        userData: userData,
        timestamp: timestamp
    };
};

/**
 * Validate a ticket, returning either its data (as per `splitTicket`) or null.
 *
 * @param {String} ticket The ticket to parse
 * @param {Object} options including `ip`, `timeout`, `encodeUserData` and
 *  `jsonUserData`.
 * @return {Object}
 */
AuthTkt.prototype.validateTicket = function(ticket, options) {
    options = options || {};
    var data, newTicket;

    var ip = options.ip || this.options.ip || '0.0.0.0',
        timeout = options.timeout || this.options.timeout || null,
        now = options.now || new Date().getTime() / 1000,
        encodeUserData = true, jsonUserData = false;

    if(options.encodeUserData !== undefined) encodeUserData = options.encodeUserData;
    else if(this.options.encodeUserData !== undefined) encodeUserData = this.options.encodeUserData;

    if(options.jsonUserData !== undefined) jsonUserData = options.jsonUserData;
    else if(this.options.jsonUserData !== undefined) jsonUserData = this.options.jsonUserData;

    try {
        data = this.splitTicket(ticket, options);
    } catch(e) {
        console.error("Invalid auth tkt: " + e);
        return null;
    }

    newTicket = this.createTicket(data.userid, {
        tokens: data.tokens,
        userData: data.userData,
        timestamp: data.timestamp,
        ip: ip,
        encodeUserData: encodeUserData,
        jsonUserData: jsonUserData
    });
    if(this.isEqual(newTicket.slice(0, 32), data.digest)) {
        if(!timeout)
            return data;
        if(data.timestamp + timeout > now)
            return data;
    }

    return null;
};

/**
 * Create an encoded ticket suitable for storing in a cookie.
 *
 * @param {String} userid User id to encode
 * @param {Object} options can contain `tokens`, `userData`, `timestamp`, and 'ip'
 * @return {String}
 */
AuthTkt.prototype.getCookie = function(userid, options) {
    return this.base64Encode(this.createTicket(userid, options));
};

/**
 * Validate a ticket, returning either its data (as per `splitTicket`) or null,
 * based on a base64-encoded cookie value
 *
 * @param {String} ticket The ticket to parse, base64 encoded
 * @param {Object} options
 * @return {Object}
 */
AuthTkt.prototype.validateCookie = function(ticket, options) {
    return this.validateTicket(this.base64Decode(ticket), options);
};

// Helpers

/**
 * Encode the given value to base65
 */
AuthTkt.prototype.base64Encode = function(tkt) {
    return new Buffer(tkt).toString('base64').trim();
};

/**
 * Decode the given value from base65
 */
AuthTkt.prototype.base64Decode = function(val) {
    return new Buffer(val, 'base64').toString('ascii');
};

/**
 * Pack a dotted quad IP address into four bytes. Return an octet array.
 */
AuthTkt.prototype.inetAton = function(ip) {
    return ip.split('.').reduce(function(memo, num) {
        return memo.concat(jspack.Pack("!B", [parseInt(num, 10)]));
    }, []);
};

/**
 * Pack a numeric timestamp into an octet array
 */
AuthTkt.prototype.packTimestamp = function(timestamp) {
    return jspack.Pack("!I", [timestamp]);
};

/**
 * Constant time comparison; avoid potential attack vector
 */
AuthTkt.prototype.isEqual = function(val1, val2) {
    if(typeof val1 != "string" || typeof val2 != "string")
        return false;

    if(val1.length != val2.length)
        return false;

    var result = 0;
    for(var i = 0; i < val1.length; ++i) {
        result |= val1[i].charCodeAt(0) ^ val2[i].charCodeAt(0);
    }

    return result === 0;
};

/**
 * Create a mod_auth_tkt digest
 */
AuthTkt.prototype.createDigest = function(secret, data1, data2) {
    var digest0 = crypto.createHash('md5').update(Buffer.concat([new Buffer(data1), new Buffer(secret), new Buffer(data2)])).digest('hex');
    var digest = crypto.createHash('md5').update(digest0 + secret).digest('hex');
    return digest;
};

module.exports = AuthTkt;