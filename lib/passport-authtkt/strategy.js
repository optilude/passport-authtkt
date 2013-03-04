/**
 * Module dependencies.
 */
var passport = require('passport'),
    util = require('util'),
    BadRequestError = require('./errors/badrequesterror'),
    authtkt = require('./authtkt');

/**
 * `Strategy` constructor.
 *
 * The AuthTkt authentication strategy authenticates requests based on the
 * presence and validity of an auth_tkt cookie.
 *
 * @param {Object} secret
 * @param {Object} options
 * @api public
 */
function Strategy(secret, options) {

    if(!secret)
        throw new Error("secret is required");

    passport.Strategy.call(this);
    this.name = 'authtkt';
    this._options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};

    var timeout = this._options.timeout || null;
    var key = this._options.key || 'authtkt';
    var ip = this._options.ip || null;

    var cookieValue = GETCOOKIE;

    if(cookieValue) {
        var ticket = authtkt.fromBase64(cookieValue);
        req.authtkt = authtkt.validateTicket(secret, ticket, timeout, ip);
    }

    if (req.authtkt) {
        var user = GETUSER;
        var info = GETINFO;
        self.success(user, info);
    } else {
        return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
    }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
