# Passport-AuthTkt

[Passport](http://passportjs.org/) strategy for authenticating with a
[mod_auth_tkt](http://www.openfusion.com.au/labs/mod_auth_tkt/) ticket cookie.

## Install

    $ npm install passport-authtkt

## Usage

#### Configure Strategy

The AuthTkt authentication strategy authenticates requests based on the
presence and validity of an auth_tkt cookie. To use it, you should configure
the `cookieParser` middleware as well as Passport:

    app.configure(function() {
        app.use(express.cookieParser());
        app.use(express.bodyParser());
        app.use(passport.initialize());
        app.use(app.router);
        app.use(express.static(__dirname + '/../../public'));
    });

To use the strategy:

    authtkt = require('passport-authtkt');

    ...

    passport.use(new authtkt.Strategy('mysecret', {
        timeout: 60*60, // 1 hour timeout; omit to not have a timeout
        encodeUserData: true,
        jsonUserData: true
    }));

Valid options include:

* `key` - name of the cookie.
* `encodeUserData - encode and decode the userData string using base64.
   Defaults to true.
* `jsonUserData` - encode and decode the userData string as JSON.
   Defaults to false.
* `ip` - use the given IP address (a dotted quad string) to create/validate
  tickets.
* `timeout` - time, in seconds, for ticket validation.

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'authtkt'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/foo', 
        passport.authenticate('authtkt', { failureRedirect: '/login' }),
        function(req, res) {
            ...
        }
    );

Note that the authenticator does not need to store anything in the session.
If you do not configure any session middleware, you should pass
`session: false` in the options to the authentication hook:

    app.post('/foo', 
        passport.authenticate('authtkt', { session: false, failureRedirect: '/login' }),
        function(req, res) {
            ...
        }
    );

When the authenticator is used, `req.authInfo` will be the parsed ticket as
 returned by `AuthTkt.splitTicket()`, assuming authentication was successful.
`req.user` will be the same as `req.authInfo.userData`.

The `AuthTkt` instance configured with the secret and options is available
as `strategy.authtkt`. This can be used e.g. to call `createTicket()` during
login.

When `req.authInfo` is set on requests where the authenticator is used, the
authentication cookie will be set if either there is a timeout configured, or
the user id, user data or tokens for the ticket in `req.authInfo` has changed.

#### Saving the ticket cookie

To create a cookie, use the helper functions `createTicket()` and
`encodeCookieValue()`:

  var authtkt = require('passport-authtkt');

  var ticket = authtkt.createTicket(secret, userId, tokens, userData, timestamp, ip);
  res.cookie('authtkt', authtkt.encodeCookieValue(ticket));

Here:

* `secret` is the encryption secret
* `userId` is the current user id
* `tokens` is a list of authentication tokens to save, which may be checked
  later. Pass an empty string if not using tokens.
* `userData` is an arbitrary string of user data to save. You may want to encode
  this; if it can contain the character `!`, it could break cookie parsing.
* `timestamp` is the timestamp to save for timeout validation purposes. Defaults
  to the current time.
* `ip` is the source ip address, again for validaton purposes.

## Tests

    $ npm install --dev
    $ make test

[![Build Status](https://secure.travis-ci.org/optilude/passport-authtkt.png)](http://travis-ci.org/optilude/passport-authtkt)

## Credits

  - [Martin Aspeli](http://github.com/optilude)
  - Based heavily on [passport-local](https://github.com/jaredhanson/passport-local) by Jared Hanson

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2013 Martin Aspeli
