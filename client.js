var http = require('http'),
    crypto = require('crypto');

// fake phant publish hash (shared secret) for stream abc123
var publish_hash = 'def456';

// req options
var options = {
  hostname: 'localhost',
  port: 8080,
  method: 'GET',
  path: '/input/abc123?wind=10&temp=98',
  headers: {
    'x-phant-fields': 'wind,temp',
    'x-phant-date': (new Date()).toISOString(),
    'x-phant-credential': 'abc123/phant_signature_v1',
    'x-phant-algorithm': 'phant-hmac-sha256'
  },
  agent: false
};

// build signature based on req options
options.headers['x-phant-signature'] = build_signature(options);

// send req
http.get(options, function(res) {

  res.on('data', function(chunk) {
    console.log('BODY: ' + chunk);
  });

});

function build_signature(opt) {

  var step1 = hmac(publish_hash, opt.headers['x-phant-date']),
      step2 = hmac(step1, opt.hostname + ':' + opt.port),
      step3 = hmac(step2, opt.method),
      step4 = hmac(step3, opt.headers['x-phant-fields']);

  // generate the signing key
  var signingKey = hmac(step4, 'phant_signature_v1');

  return hmac(signingKey, opt.path.split('?')[1]);

};

function hmac(key, data) {

  // create new hmac
  var h = crypto.createHmac('sha256', key);

  // hash data
  return h.update(data).digest('hex');

}
