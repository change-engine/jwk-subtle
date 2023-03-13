function b64decode(b64: string): string {
  return atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
}

function toUint8Array(s: string): Uint8Array {
  return new Uint8Array([...s].map((ch) => ch.charCodeAt(0)));
}
export async function verify<T>(token: string, iss: string, aud: string): Promise<T | false> {
  const [_head, _claims, sig] = token.split('.');
  const head = JSON.parse(b64decode(_head)) as {
    typ: string;
    alg: string;
    kid: string;
  };
  if (head.typ !== 'JWT') return false;
  if (head.alg !== 'RS256') return false;
  const jwksRequest = await fetch(`${iss}.well-known/jwks.json`);
  const jwks = (await jwksRequest.json()) as {
    keys: (JsonWebKey & {
      kid: string;
    })[];
  };
  const key = Object.fromEntries(jwks.keys.map((k) => [k.kid, k]))[head.kid];
  if (!key) return false;
  if (key.alg !== 'RS256') return false;
  if (
    !(await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      await crypto.subtle.importKey('jwk', key, { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, false, [
        'verify',
      ]),
      toUint8Array(sig),
      toUint8Array(`${_head}.${_claims}`),
    ))
  )
    return false;
  const claims = JSON.parse(b64decode(_claims)) as T & {
    nbf?: number;
    exp?: number;
    iss: string;
    aud: string[];
  };
  if (claims.nbf && claims.nbf > Math.floor(Date.now() / 1000)) return false;
  if (claims.exp && claims.exp <= Math.floor(Date.now() / 1000)) return false;
  if (claims.iss !== iss) return false;
  if (!claims.aud.includes(aud)) return false;
  return claims;
}
