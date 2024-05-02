## Auth Middleware

This repository contains an implementation of JWT auth middleware written in Go.
The structure of this middleware is such that it allows you to specify "authFuncs" which implement validation logic on the token's claims as you wish it to be.

Also includes a version of the middleware compatible with [chi](https://github.com/go-chi/chi).

Dependencies:

- https://github.com/go-chi/chi
- https://github.com/cristalhq/jwt
