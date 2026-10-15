# Configuration

## Token signing key

The `auth serve` command requires `--signing-key`. Pass a newly generated RSA private key as PEM text. The key must use the PKCS#1 encoding produced by `openssl genrsa` or `openssl genpkey -traditional`.

Generate a key and inject its contents through the deployment secret mechanism:

```sh
openssl genrsa -traditional -out auth-signing-key.pem 4096
auth serve --signing-key "$(cat auth-signing-key.pem)"
```

Do not store the private key in the repository, a container image, or command output. The service refuses to start when the flag is empty, the PEM cannot be decoded, the key is not a PKCS#1 RSA private key, or the key matches the compromised legacy key removed from this repository.

The service derives the JSON Web Key Set (JWKS) `kid` from the SHA-256 digest of the public key. Replacing the private key therefore publishes a new `kid` and invalidates tokens signed with the previous key. Services that validate Auth tokens must refresh their JWKS cache after a rotation.

## Migration from the embedded key

Deployments that relied on the former embedded default must inject a new key before upgrading. Tokens signed by the former key must no longer be accepted. Coordinate the Auth rollout with downstream token validators so they load the new JWKS before normal traffic resumes.

## Token revocation

Send an `application/x-www-form-urlencoded` POST to `/revoke` with the token in the `token` parameter and the authentication required for its issuing client. Confidential clients must authenticate, for example with HTTP Basic client credentials. Only the issuing client can revoke the token; a request from another client returns `401 invalid_client` and leaves the token intact.

The `token_type_hint` parameter is optional. Auth ignores it and first looks for a refresh token, then resolves an access token. This follows [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1) and permits revocation with an absent, incorrect or unknown hint. Successful revocation returns HTTP `200`. An unknown or already revoked token also returns `200`.

Revoking an access token deletes its stored token record. Its refresh token, if present, remains valid. Revoking a refresh token deletes both that refresh token and all stored access tokens derived from it. A later `grant_type=refresh_token` request with the revoked refresh token returns `400 invalid_grant`. Tokens associated with a different refresh token remain intact.

Auth endpoints that consult stored access tokens, such as `/userinfo`, reject them after deletion. Revocation does not invalidate a JWT's signature. A consumer that checks only the signature and expiry can continue accepting a revoked access token until it expires; immediate revocation requires the consumer to check token state as well.

New JWT bearer access tokens retain the identity of the authenticated issuing client. Assertion claims such as `client_id` and `azp` do not select the token owner. JWT bearer tokens issued before this fix may have an empty stored `ApplicationID`. Auth does not backfill these records from assertion claims: the client's `/revoke` request cannot revoke them, and they remain subject to their original expiry.
