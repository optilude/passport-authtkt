/**
 * Module dependencies.
 */
var Strategy        = require('./strategy'),
    BadRequestError = require('./errors/badrequesterror'),
    AuthTkt         = require('./authtkt'),
    authtktUtils    = require('./authtktutils');
/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors and helpers
 */
exports.Strategy = Strategy;
exports.BadRequestError = BadRequestError;

exports.AuthTkt = AuthTkt;
exports.utils = authtktUtils;
