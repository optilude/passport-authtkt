var vows = require('vows');
var assert = require('assert');
var util = require('util');
var AuthTktStrategy = require('passport-authtkt/strategy');
var BadRequestError = require('passport-authtkt/errors/badrequesterror');


vows.describe('AuthTktStrategy').addBatch({

    'strategy': {
        topic: new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789'),
        
        'should be named authtkt': function (strategy) {
            assert.equal(strategy.name, 'authtkt');
        },

        'strategy handling a request without cookie middleware set up': {
            topic: function() {
                return new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789');
            },
    
            'after augmenting with actions': {
                topic: function(strategy) {
                    var self = this;
                    var req = {};
                    strategy.success = function(user, info) {
                      self.callback(null, req, user, info);
                    };

                    strategy.fail = function() {
                      self.callback(new Error('should-not-be-called'), req);
                    };
                
                    req.res = {};
                    req.res.on = function(event, fn) {

                    };
                    req.res.clearCookie = function(name) {

                    };
                
                    process.nextTick(function () {
                        try {
                            strategy.authenticate(req);
                        } catch(e) {
                            self.callback(e, req);
                        }
                    });
                },
          
                'should fail' : function(err, req, user, info) {
                    assert.isNotNull(err);
                },
                
                'should not set authInfo' : function(err, req, user, info) {
                    assert.isUndefined(req.authInfo);
                }
            }
        },

        'strategy handling a request with default options and no cookie': {
            topic: function() {
                return new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789');
            },
    
            'after augmenting with actions': {
                topic: function(strategy) {
                    var self = this;
                    var req = {};
                    strategy.success = function(user, info) {
                      self.callback(null, req, user, info);
                    };

                    strategy.fail = function() {
                      self.callback(new Error('should-not-be-called'), req);
                    };
                
                    req.cookies = {};
                    req.res = {};
                    req.res.on = function(event, fn) {

                    };
                    req.res.clearCookie = function(name) {

                    };
                
                    process.nextTick(function () {
                        strategy.authenticate(req);
                    });
                },
          
                'should fail' : function(err, req, user, info) {
                    assert.isNotNull(err);
                },
                
                'should not set authInfo' : function(err, req, user, info) {
                    assert.isUndefined(req.authInfo);
                }
            }
        }
  }
}).export(module);