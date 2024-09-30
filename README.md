# basic-auth-connect

Connect's Basic Auth middleware in its own module. You should consider to create your own middleware with [basic-auth](https://github.com/visionmedia/node-basic-auth).

## API

```js
var basicAuth = require('basic-auth-connect');
```

Simple username and password

```js
connect()
.use(basicAuth('username', 'password'));
```

Callback verification

```js
connect()
.use(basicAuth(function(user, pass){
  return 'tj' == user && 'wahoo' == pass;
}))
```

Async callback verification, accepting `fn(err, user)`.

```js
connect()
.use(basicAuth(function(user, pass, fn){
  User.authenticate({ user: user, pass: pass }, fn);
}))
```

**Security Considerations**

Important: When using the callback method, it is recommended to use a time-safe comparison function like [crypto.timingSafeEqual](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b) to prevent timing attacks.

## License

[MIT](./LICENSE)
