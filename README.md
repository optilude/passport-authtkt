# Passport-AuthTkt

[Passport](http://passportjs.org/) strategy for authenticating with a
[mod_auth_tkt](http://www.openfusion.com.au/labs/mod_auth_tkt/) ticket cookie.

## Install

    $ npm install passport-authtkt

## Usage

#### Configure Strategy

The AuthTkt strategy authenticates users using a ticket set in a cookie.

    passport.use(new AuthTktStrategy('secret'));

The first arugment is a string containing a secret, used to encrypt the cookie.
This argument is required.

An optional second argument can be given with options:

  passport.use(new AuthTktStrategy('secret', {
    timeout: 60*60*3, // time out after 3 hours
    key: '_auth',     // cookie name, defaults to 'authtkt'
    ip: '127.0.0.1'   // validate cookie against this IP address
  });

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'authtkt'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/members',
      passport.authenticate('authtkt', { failureRedirect: '/login' }),
      function(req, res) {
        ...
      });

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
