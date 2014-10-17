var crypto = require('crypto'),
    http = require('http'),
    parse = require('url').parse;

http.createServer(function(req, res) {

  var url = parse(req.url);

  // send current timestamp for clients without RTCs
  if(url.pathname === '/date') {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    return res.end((new Date()).toISOString() + '\n');
  }

  // only respond to one stream path
  if(url.pathname != '/input/abc123') {
    res.writeHead(404, {'Content-Type': 'text/plain'});
    return res.end('not found. use http://127.0.0.1:8080/input/abc123 to test.\n');
  }

  // check signature
  if(!verify(req)) {
    res.writeHead(403, {'Content-Type': 'text/plain'});
    return res.end('forbidden.\n');
  }

  // everything is ok
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('success.\n');

}).listen(8080, '127.0.0.1');

function verify(req) {

  // parsed url to check fields
  var url = parse(req.url, true);

  // fake phant publish hash (shared secret) for stream abc123
  var publish_hash = 'def456';

  // window in ms for a valid request
  var win = 15 * 60 * 1000;

  // current time in ms
  var now = new Date().getTime();

  // acceptable algorithms
  var algorithms = {
    'phant-hmac-sha1': 'sha1',
    'phant-hmac-sha256': 'sha256',
    'phant-hmac-sha512': 'sha512'
  };

  // get the header values
  var req_host = req.headers['host'],
      req_credential = req.headers['x-phant-credential'], // abc123/phant_signature_v1
      req_algorithm = req.headers['x-phant-algorithm'], // check algorithms obj keys above
      req_fields = req.headers['x-phant-fields'], // comma separated fields sent
      req_date = req.headers['x-phant-date'], // ISO-8601 Date
      req_signature = req.headers['x-phant-signature'],
      req_method = req.method;

  // make sure all required headers were sent
  if(!req_credential || !req_algorithm || !req_fields || !req_date || !req_signature) {
    console.error('missing header');
    return false;
  }

  // parse values
  req_fields = req_fields.split(',').map(function(f) { return f.trim().toLowerCase(); });
  req_algorithm = req_algorithm.trim().toLowerCase();
  req_date = new Date(req_date.trim());
  req_credential = req_credential.split('/').map(function(c) { return c.trim().toLowerCase(); });

  // make sure they are using the right signature version
  if(req_credential[1] !== 'phant_signature_v1') {
    console.error('wrong signature version');
    return false;
  }

  // check to make sure a valid algorithm was defined
  if(Object.keys(algorithms).indexOf(req_algorithm) === -1) {
    console.error('invalid algorithm');
    return false;
  }

  // grab the node compatible algorithm name
  req_algorithm = algorithms[req_algorithm];

  // make sure we are authenticating the same stream
  if(url.pathname.replace('/input/', '') !== req_credential[0]) {
    console.error('credentials don\'t match the current stream');
    return false;
  }

  // make sure date was able to be parsed
  if(isNaN(req_date)) {
    console.error('date could not be parsed');
    return false;
  }

  // make sure we are within time window for the request
  if(req_date < (now - win) || req_date > (now + win)) {
    console.log('date was outside window');
    return false;
  }

  // grab the field names from the sent values
  var query = Object.keys(url.query);

  // make sure fields header length matches query string keys length
  if(req_fields.length !== query.length) {
    console.error('fields header length doesn\'t match query string length');
    return false;
  }

  // make sure fields header and query string fields match
  for(var i=0; i < query.length; i++) {

    if(req_fields.indexOf(query[i].toLowerCase()) === -1) {
      console.error('fields header doesn\'t match query string');
      return false;
    }

  }

  // build up signing key
  var step1 = hmac(req_algorithm, publish_hash, req.headers['x-phant-date'].trim()),
      step2 = hmac(req_algorithm, step1, req_host),
      step3 = hmac(req_algorithm, step2, req_method),
      step4 = hmac(req_algorithm, step3, req.headers['x-phant-fields'].trim());

  // generate the signing key
  var signingKey = hmac(req_algorithm, step4, 'phant_signature_v1');

  // generate the signature to compare
  var signature = hmac(req_algorithm, signingKey, url.search.replace('?', ''));

  // check if they match
  if(signature !== req_signature.trim()) {
    console.error('signature doesn\'t match');
    return false
  }

  return true;

}

function hmac(alg, key, data) {

  // create new hmac
  var h = crypto.createHmac(alg, key);

  // hash data
  return h.update(data).digest('hex');

}

console.log('Server running at http://127.0.0.1:8080/')
