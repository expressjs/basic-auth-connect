
var request = require('supertest');
var connect = require('connect');
var basicAuth = require('./');

function test(app, signature) {
  describe(signature, function(){
    describe('when missing Authorization', function(){
      it('should respond with 401 and WWW-Authenticate', function(done){
        request(app)
        .get('/')
        .end(function(err, res){
          res.statusCode.should.equal(401);
          res.headers['www-authenticate'].should.equal('Basic realm="Authorization Required"');
          done();
        });
      })
    })

    describe('when valid', function(){
      it('should next()', function(done){
        request(app)
        .get('/')
        .set('Authorization', 'Basic dGo6dG9iaTpsZWFybmJvb3N0')
        .end(function(err, res){
          res.statusCode.should.equal(200);
          res.text.should.equal('secret!');
          done();
        });
      })
    })

    describe('when invalid credentials', function(){
      it('should respond with 401', function(done){
        request(app)
        .get('/')
        .set('Authorization', 'Basic dGo69iaQ==')
        .end(function(err, res){
          res.statusCode.should.equal(401);
          res.headers['www-authenticate'].should.equal('Basic realm="Authorization Required"');
          res.text.should.equal('Unauthorized');
          done();
        });
      })
    })

    describe('when authorization header is not Basic', function(){
      it('should respond with 400', function(done){
        request(app)
        .get('/')
        .set('Authorization', 'Digest dGo69iaQ==')
        .end(function(err, res){
          res.statusCode.should.equal(400);
          res.text.should.match(/Bad Request/);
          done();
        });
      })
    })

    describe('when authorization header is malformed - contains only one part', function(){
      it('should respond with 400', function(done){
        request(app)
        .get('/')
        .set('Authorization', 'invalid')
        .end(function(err, res){
          res.statusCode.should.equal(400);
          res.text.should.match(/Bad Request/);
          done();
        });
      })
    })
  })
}

var app = connect();

app.use(basicAuth('tj', 'tobi:learnboost'));

app.use(function(req, res, next){
  req.user.should.equal('tj');
  res.end('secret!');
});

test(app, 'basicAuth(user, pass)');



var app = connect();

app.use(basicAuth(function(user, pass){
  return 'tj' == user && 'tobi:learnboost' == pass;
}));

app.use(function(req, res, next){
  req.user.should.equal('tj');
  res.end('secret!');
});

test(app, 'basicAuth(callback)');



var app = connect();

app.use(basicAuth(function(user, pass, fn){
  var ok = 'tj' == user && 'tobi:learnboost' == pass;
  fn(null, ok
    ? { name: 'tj' }
    : null);
}));

app.use(function(req, res, next){
  req.user.name.should.equal('tj');
  res.end('secret!');
});

test(app, 'basicAuth(callback) async');
