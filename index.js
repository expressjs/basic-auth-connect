const http = require('http');
const crypto = require('crypto');

/*!
 * Connect - basicAuth
 * Copyright(c) 2010 Sencha Inc.
 * Copyright(c) 2011 TJ Holowaychuk
 * Copyright(c) 2024 Ulises Gascón
 * MIT Licensed
 */

/**
 * Basic Auth:
 * 
 * Enfore basic authentication by providing a `callback(user, pass)`,
 * which must return `true` in order to gain access. Alternatively an async
 * method is provided as well, invoking `callback(user, pass, callback)`. Populates
 * `req.user`. The final alternative is simply passing username / password
 * strings.
 *
 *  Simple username and password
 *
 *     connect(connect.basicAuth('username', 'password'));
 *
 *  Callback verification
 *
 *     connect()
 *       .use(connect.basicAuth(function(user, pass){
 *         return 'tj' === user && 'wahoo' === pass;
 *       }))
 *  
 *  Note: it is recommended to use `crypto.timingSafeEqual(a, b)` https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b
 *
 *  Async callback verification, accepting `fn(err, user)`.
 *
 *     connect()
 *       .use(connect.basicAuth(function(user, pass, fn){
 *         User.authenticate({ user: user, pass: pass }, fn);
 *       }))
 *
 * @param {Function|String} callback or username
 * @param {String} realm
 * @api public
 */

module.exports = function basicAuth(callback, realm) {
  let username, password;

  // user / pass strings
  if (typeof callback === 'string') {
    username = callback;
    password = realm;
    if (typeof password !== 'string') throw new Error('password argument required');
    realm = arguments[2];

    callback = (user, pass) => {
      const buffers = [
        Buffer.from(user),
        Buffer.from(pass),
        Buffer.from(username),
        Buffer.from(password)
      ];

      // Determine the maximum length among all buffers
      const maxLength = Math.max(...buffers.map(buf => buf.length));
      
      // Pad each buffer to the maximum length
      const paddedBuffers = buffers.map(buf => Buffer.concat([buf, Buffer.alloc(maxLength - buf.length)]));
    
      const usernameValid = crypto.timingSafeEqual(paddedBuffers[0], paddedBuffers[2])
      const passwordValid = crypto.timingSafeEqual(paddedBuffers[1], paddedBuffers[3])
      return usernameValid && passwordValid;
    };
  }

  realm = realm || 'Authorization Required';

  return (req, res, next) => {
    const authorization = req.headers.authorization;

    if (req.user) return next();
    if (!authorization) {
      unauthorized(res, realm);
      return;
    }

    const parts = authorization.split(' ');

    if (parts.length !== 2) return next(error(400));

    const scheme = parts[0];
    const credentials = Buffer.from(parts[1], 'base64').toString();
    const index = credentials.indexOf(':');

    if (scheme !== 'Basic' || index < 0) return next(error(400));

    const user = credentials.slice(0, index);
    const pass = credentials.slice(index + 1);

    // async
    if (callback.length >= 3) {
      callback(user, pass, (err, user) => {
        if (err || !user) {
          unauthorized(res, realm);
          return;
        }
        req.user = req.remoteUser = user;
        next();
      });
    // sync
    } else {
      if (callback(user, pass)) {
        req.user = req.remoteUser = user;
        next();
      } else {
        unauthorized(res, realm);
      }
    }
  }
};

/**
 * Respond with 401 "Unauthorized".
 *
 * @param {ServerResponse} res
 * @param {String} realm
 * @api private
 */
function unauthorized(res, realm) {
  res.statusCode = 401;
  res.setHeader('WWW-Authenticate', `Basic realm="${realm}"`);
  res.end('Unauthorized');
}

/**
 * Generate an `Error` from the given status `code`
 * and optional `msg`.
 *
 * @param {Number} code
 * @param {String} msg
 * @return {Error}
 * @api private
 */
function error(code, msg) {
  const err = new Error(msg || http.STATUS_CODES[code]);
  err.status = code;
  return err;
}