/**
 * Module dependencies.
 */
var passport = require('passport'),
    util = require('util'),
    BadRequestError = require('./errors/badrequesterror'),
    AuthTkt = require('./authtkt'),
    _ = require('underscore');

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
 * When the authenticator is used, `req.authInfo` will be the parsed ticket as
 *  returned by `AuthTkt.splitTicket()`, assuming authentication was successful.
 * `req.user` will be the same as `req.authInfo.userData`.
 *
 * The `AuthTkt` instance configured with the secret and options is available
 * as `strategy.authtkt`. This can be used e.g. to call `createTicket()` during
 * login.
 *
 * Options:
 *   - `key`               Name of the cookie.
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
    options = options || {};

    if(!secret)
        throw new Error("secret is required");

    passport.Strategy.call(this);
    this.name = 'authtkt';
    this.authtkt = new AuthTkt(secret, options);
    this.key = options.key || 'authtkt';
    this.options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the presence of an authentication cookie
 *
 * @param {Object} req the request
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options =_.extend({
        timeout: null,
        ip: '0.0.0.0',
        tokens: []
    }, this.options, options || {});

    var cookieValue = req.cookies[this.key],
        strategy = this,
        authInfo;

    if(cookieValue) {
        authInfo = this.authtkt.validateCookie(cookieValue, options);
    }

    var success = null;

    if (authInfo) {
        this.success(authInfo.userData, _.clone(authInfo));
        success = true;
    } else {
        this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
        success = false;
    }

    // Refresh the cookie on response if necessary
    req.res.on('header', function() {
        if(req.authInfo) {
            var userid = req.authInfo.userid;
            var userData = req.authInfo.userData;
            var tokens = req.authInfo.tokens;

            // We don't want to set the cookie if nothing's changed and we
            // are not refreshing for use with a timeout
            if(options.timeout || !authInfo ||
               !_.isEqual(userid, authInfo.userid) ||
               !_.isEqual(userData, authInfo.userData) ||
               !_.isEqual(tokens, authInfo.tokens)
            ) {
                var newCookieValue = this.authtkt.getCookie(userid, _.extend(options, {
                    userData: userData,
                    tokens: tokens
                }));
                res.cookie(strategy.key, cookieValue);
            }
        }
    });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
