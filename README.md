# basic-auth-connect

Connect's Basic Auth middleware in its own module. This module is considered deprecated. You should instead create your own middleware with [basic-auth](https://github.com/visionmedia/node-basic-auth).

## API

```js
var basicAuth = require('basic-auth-connect');
```

Sorry, couldn't think of a more clever name.

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

```
connect()
.use(basicAuth(function(user, pass, fn){
  User.authenticate({ user: user, pass: pass }, fn);
}))
```

## License

[MIT](./LICENSE)
