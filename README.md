# jwt-subtle

Verify RS256 JWT. Uses only `crypto.subtle`.

## To check the Authorization header:

```typescript
const [scheme, token] = (request.headers.get("Authorization") ?? " ").split(" ");
if (scheme !== "Bearer") new Response("", { status: 401 });
const claims = await verify(token, "https://example.eu.auth0.com/", "http://example.com");
if (!claims) return new Response("", { status: 401 });
```
>>>>>>> 9bda056 (init)
