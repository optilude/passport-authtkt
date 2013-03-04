/**
 * Module dependencies.
 */
var Strategy = require('./strategy'),
    BadRequestError = require('./errors/badrequesterror'),
    authtkt = require('./authtkt');

/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors and helpers
 */
exports.Strategy = Strategy;
exports.BadRequestError = BadRequestError;

exports.createTicket = authtkt.createTicket;
exports.splitTicket = authtkt.splitTicket;
exports.validateTicket = authtkt.validateTicket;
exports.encodeCookieValue = authtkt.toBase64;
exports.decodeCookieValue = authtkt.fromBase64;
