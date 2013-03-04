var vows = require('vows');
var assert = require('assert');
var util = require('util');
var authtkt = require('passport-authtkt');


vows.describe('passport-authtkt').addBatch({

  'module': {
    'should report a version': function (x) {
      assert.isString(authtkt.version);
    },

    'should export BadRequestError': function (x) {
      assert.isFunction(authtkt.BadRequestError);
    }
  }

}).export(module);
