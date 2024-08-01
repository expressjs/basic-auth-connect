# basic-auth-connect

Connect's Basic Auth middleware in its own module. You should consider to create your own middleware with [basic-auth](https://github.com/visionmedia/node-basic-auth).

It requires Node.js 18.x or higher.

## Installation

```bash
npm install basic-auth-connect
```

## API

Import the module

```js
const basicAuth = require('basic-auth-connect');
```

Simple username and password

```js
const connect = require('connect');

const app = connect()
  .use(basicAuth('username', 'password'))
  .use((req, res) => {
    res.end('Authenticated!');
  });

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

Callback verification

```js
const connect = require('connect');

const app = connect()
  .use(basicAuth((user, pass) => {
    return user === 'tj' && pass === 'wahoo';
  }))
  .use((req, res) => {
    res.end('Authenticated!');
  });

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
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

## Running Tests

To run the tests, use the following command:

```bash
npm test
```

This will execute the tests defined in the [Makefile](./Makefile) using Mocha.


## License

This project is licensed under the MIT License. See theç [LICENSE](./LICENSE) file for details.
