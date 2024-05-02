## Auth Middleware

Purpose:
This is a library implementing simple JWT-authentication middleware functions for Go microservice applications. It is part of my investigation in different approaches to implement such middleware.

All implementations currently are based on the [jwt](https://github.com/cristalhq/jwt) library by cristalhq. This library was chosen as a no nonsense, minimalistic JWT signing and validation library.
(Potentially might implement solutions for golang-jwt's jwt lib in a sister library)

- The first approach is based on a single, configurable middleware function. The function takes in a series of `Validator` functions, which accept a `TokenClaims` object containing a JWT's claims and perform checks on it based on it's fields.
- The second approach instead relies on a series of middleware functions which individually are concerned with different topics:
  1. `Verify`: Retrieve the token from the `Authentication` token, verify signature, load it into context.
  2. `LoadClaims`: Parse the claims from the token and load them into context for ease of use further down the middleware stack.
  3. `WithPermissions`: Check the `permissions` claim to verify an entity trying to access the endpoint protected by the middleware has the specified permissions in it's token.

In both approaches, there are two implementations:

1. A version designed to work seamlessly with the Go stdlib
2. A version designed to work with [chi](https://github.com/go-chi/chi).

Dependencies:

- https://github.com/cristalhq/jwt
