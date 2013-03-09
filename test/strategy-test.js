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

        'strategy handling a request without cookie middleware configured': {
        
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user, info) {
                    self.callback(null, req, user, info);
                };

                strategy.fail = function() {
                    self.callback(new Error('should-be-called'), req);
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
        },

        'strategy handling a request with cookie middleware configured': {
            topic: function() {
                return new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789');
            },
    
            'after augmenting with actions': {
                topic: function(strategy) {
                    var self = this;
                    var req = {};
                    strategy.success = function(user, info) {
                        req.authInfo = info;
                        self.callback(null, req, user, info);
                    };

                    strategy.fail = function() {
                        self.callback(new Error('should-be-called'), req);
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
        },

        'strategy handling a request with default options and an invalid cookie': {
            topic: function() {
                return new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789');
            },
    
            'after augmenting with actions': {
                topic: function(strategy) {
                    var self = this;
                    var req = {};
                    strategy.success = function(user, info) {
                        req.authInfo = info;
                        self.callback(null, req, user, info);
                    };

                    strategy.fail = function() {
                        self.callback(new Error('should-be-called'), req);
                    };
                
                    req.cookies = {
                        authtkt: 'foo'
                    };
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
        },

        'strategy handling a request with default options and a basic ticket': {
            topic: function() {
                return new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789');
            },
    
            'after augmenting with actions': {
                topic: function(strategy) {
                    var self = this;
                    var req = {};
                    strategy.success = function(user, info) {
                        req.authInfo = info;
                        self.callback(null, req, user, info);
                    };

                    strategy.fail = function() {
                        self.callback(new Error('should-not-be-called'), req);
                    };
                
                    req.cookies = {
                        authtkt: 'YzdjNzMwMGFjNWNmNTI5NjU2NDQ0MTIzYWNhMzQ1Mjk0ODg1YWZhMGpibG9nZ3Mh'
                    };
                    req.res = {};
                    req.res.on = function(event, fn) {

                    };
                    req.res.clearCookie = function(name) {

                    };
                
                    process.nextTick(function () {
                         strategy.authenticate(req);
                    });
                },
          
                'should not fail' : function(err, req, user, info) {
                    assert.isNull(err);
                },
                
                'should set authInfo' : function(err, req, user, info) {
                    assert.deepEqual(info, {
                        digest: 'c7c7300ac5cf529656444123aca34529',
                        userid: 'jbloggs',
                        tokens: [],
                        userData: '',
                        timestamp: 1216720800
                    });
                },

                'should set req.authInfo' : function(err, req, user, info) {
                    assert.deepEqual(req.authInfo, {
                        digest: 'c7c7300ac5cf529656444123aca34529',
                        userid: 'jbloggs',
                        tokens: [],
                        userData: '',
                        timestamp: 1216720800
                    });
                },

                'should set user to be the user data' : function(err, req, user, info) {
                    assert.equal(user, '');
                }
            }
        },

        'strategy handling a request with options passed to authtkt': {
            topic: function() {
                return new AuthTktStrategy('abcdefghijklmnopqrstuvwxyz0123456789', {
                    encodeUserData: false
                });
            },
    
            'after augmenting with actions': {
                topic: function(strategy) {
                    var self = this;
                    var req = {};
                    strategy.success = function(user, info) {
                        req.authInfo = info;
                        self.callback(null, req, user, info);
                    };

                    strategy.fail = function() {
                        self.callback(new Error('should-not-be-called'), req);
                    };
                
                    req.cookies = {
                        authtkt: 'ZWVhMzYzMGU5ODE3N2JkYmYwZTdmODAzZTE2MzJiN2U0ODg1YWZhMGpibG9nZ3MhZm9vLGJhciFKb2UgQmxvZ2dz'
                    };
                    req.res = {};
                    req.res.on = function(event, fn) {

                    };
                    req.res.clearCookie = function(name) {

                    };
                
                    process.nextTick(function () {
                         strategy.authenticate(req);
                    });
                },
          
                'should not fail' : function(err, req, user, info) {
                    assert.isNull(err);
                },
                
                'should set authInfo' : function(err, req, user, info) {
                    assert.deepEqual(info, {
                        digest: 'eea3630e98177bdbf0e7f803e1632b7e',
                        userid: 'jbloggs',
                        tokens: ['foo', 'bar'],
                        userData: 'Joe Bloggs',
                        timestamp: 1216720800
                    });
                },

                'should set req.authInfo' : function(err, req, user, info) {
                    assert.deepEqual(req.authInfo, {
                        digest: 'eea3630e98177bdbf0e7f803e1632b7e',
                        userid: 'jbloggs',
                        tokens: ['foo', 'bar'],
                        userData: 'Joe Bloggs',
                        timestamp: 1216720800
                    });
                },

                'should set user to be the user data' : function(err, req, user, info) {
                    assert.equal(user, 'Joe Bloggs');
                }
            }
        }
    }
}).export(module);