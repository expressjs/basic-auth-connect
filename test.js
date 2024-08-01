const request = require('supertest');
const connect = require('connect');
const basicAuth = require('./');

const test = (app, signature) => {
  describe(signature, () => {
    describe('when missing Authorization', () => {
      it('should respond with 401 and WWW-Authenticate', (done) => {
        request(app)
          .get('/')
          .end((err, res) => {
            res.statusCode.should.equal(401);
            res.headers['www-authenticate'].should.equal('Basic realm="Authorization Required"');
            done();
          });
      });
    });

    describe('when valid', () => {
      it('should next()', (done) => {
        request(app)
          .get('/')
          .set('Authorization', 'Basic dGo6dG9iaTpsZWFybmJvb3N0')
          .end((err, res) => {
            res.statusCode.should.equal(200);
            res.text.should.equal('secret!');
            done();
          });
      });
    });

    describe('when invalid credentials', () => {
      it('should respond with 401', (done) => {
        request(app)
          .get('/')
          .set('Authorization', 'Basic dGo69iaQ==')
          .end((err, res) => {
            res.statusCode.should.equal(401);
            res.headers['www-authenticate'].should.equal('Basic realm="Authorization Required"');
            res.text.should.equal('Unauthorized');
            done();
          });
      });
    });

    describe('when authorization header is not Basic', () => {
      it('should respond with 400', (done) => {
        request(app)
          .get('/')
          .set('Authorization', 'Digest dGo69iaQ==')
          .end((err, res) => {
            res.statusCode.should.equal(400);
            res.text.should.match(/Bad Request/);
            done();
          });
      });
    });

    describe('when authorization header is malformed - contains only one part', () => {
      it('should respond with 400', (done) => {
        request(app)
          .get('/')
          .set('Authorization', 'invalid')
          .end((err, res) => {
            res.statusCode.should.equal(400);
            res.text.should.match(/Bad Request/);
            done();
          });
      });
    });
  });
};

let app = connect();

app.use(basicAuth('tj', 'tobi:learnboost'));

app.use((req, res, next) => {
  req.user.should.equal('tj');
  res.end('secret!');
});

test(app, 'basicAuth(user, pass)');

app = connect();

app.use(basicAuth((user, pass) => 'tj' === user && 'tobi:learnboost' === pass));

app.use((req, res, next) => {
  req.user.should.equal('tj');
  res.end('secret!');
});

test(app, 'basicAuth(callback)');

app = connect();

app.use(basicAuth((user, pass, fn) => {
  const ok = 'tj' === user && 'tobi:learnboost' === pass;
  fn(null, ok ? { name: 'tj' } : null);
}));

app.use((req, res, next) => {
  req.user.name.should.equal('tj');
  res.end('secret!');
});

test(app, 'basicAuth(callback) async');
