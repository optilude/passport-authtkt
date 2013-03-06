/**
 * Module dependencies.
 */
var passport = require('passport'),
    util = require('util'),
    BadRequestError = require('./errors/badrequesterror'),
    AuthTkt = require('./authtkt');

/**
 * `Strategy` constructor.
 *
 * The AuthTkt authentication strategy authenticates requests based on the
 * presence and validity of an auth_tkt cookie.
 * 
 * You should configure the `cookieParser` middleware as well as Passport:
 *
 *     app.configure(function() {
 *         app.use(express.cookieParser());
 *         app.use(express.bodyParser());
 *         app.use(passport.initialize());
 *         app.use(app.router);
 *         app.use(express.static(__dirname + '/../../public'));
 *     });
 *
 * To use the strategy:
 *
 *     authtkt = require('passport-authtkt');
 *
 *     ...
 *
 *     passport.use(new authtkt.Strategy('mysecret', {
 *         timeout: 60*60, // 1 hour timeout; omit to not have a timeout
 *         encodeUserData: true,
 *         jsonUserData: true
 *     }));
 *
 * To use the authentication:
 *
 *     app.post('/foo', 
 *         passport.authenticate('authtkt', { failureRedirect: '/login' }),
 *         function(req, res) {
 *             ...
 *         }
 *     );
 *
 * When the authenticator is used, the variable `req.authtkt` will be the
 * configured `AuthTkt` instance, which can be used to create new tickets.
 * See `authtkt.js`. `req.authInfo` will be the parsed ticket as returned by
 * `req.authtkt.splitTicket()`, assuming authentication was successful.
 * `req.user` will be the same as `req.authInfo.userData`.
 *
 * Options:
 *   - `key`               Name of the cookie.
 *   - `assignProperty`    Assign the decoded auth ticket to the given value
 *   - `encodeUserData`    Encode and decode the userData string using base64.
 *                         Defaults to true.
 *   - `jsonUserData`      Encode and decode the userData string as JSON.
 *                         Defaults to false.
 *   - `ip`                Use the given IP address (a dotted quad string)
 *                         to create/validate tickets.
 *   - `timeout`           Time, in seconds, for ticket validation.
 *
 * @param {Object} secret The server-side authentication secret
 * @param {Object} options Options hash
 * @api public
 */
function Strategy(secret, options) {

    if(!secret)
        throw new Error("secret is required");

    passport.Strategy.call(this);
    this.name = 'authtkt';
    this.authtkt = new AuthTkt(secret, options);
    this._options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the presence of an authentication cookie
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};

    var timeout = this._options.timeout || null;
    var key = this._options.key || 'authtkt';
    var ip = this._options.ip || null;

    // Save the auth ticket utility for later use e.g. by the login function
    req.authtkt = this.authtkt;

    var cookieValue = req.cookies[key], authInfo;

    if(cookieValue) {
        authInfo = authtkt.validateCookie(secret, ticket, timeout, ip);
    }

    if (authInfo) {
        self.success(authInfo.userData, authInfo);
    } else {
        this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
    }

    // TODO: Need to set cookie on response

};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
