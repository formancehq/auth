# Configuration

## Scope rollout: token issuance

For `client_credentials`, omitting the `scope` parameter grants the scopes
configured on the authenticated client. This default applies to both database
clients and static clients. It lets existing callers receive their configured
scopes without changing their token request during the first rollout phase.

When `scope` is present, Auth grants only the intersection of requested and
configured scopes. An explicitly empty `scope` (`scope=`) is malformed and
returns HTTP 400 with the OAuth error `invalid_scope`, without issuing a token.
Omission and an empty value are distinct: the documented default applies only
to omission, as permitted by [RFC 6749 section 3.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
A client with no configured scopes receives no scopes, including when it requests
privileged scopes. Changing client configuration affects newly issued tokens; existing
tokens are not rewritten.

JWT access tokens carry granted resource scopes in the space-delimited `scope`
claim. The existing OIDC library excludes userinfo scopes (`profile`, `email`,
`address`, `phone`) from this claim; their OIDC userinfo behavior is unchanged.
Authorization-code, refresh-token and delegated JWT-bearer flows retain their
existing scope rules. In particular, the delegated JWT-bearer flow carries the
scopes of the trusted assertion rather than adopting the client-credentials
defaults.

## Mandatory scope checks

Auth always checks scopes on authenticated management API routes. Read requests
require `auth:read` or `auth:write`; write requests require `auth:write`.
A valid token with missing or unrelated scopes receives HTTP 401.

The `--auth-check-scopes` flag has been removed. Remove it from deployment
arguments, including explicit `true` or `false` values, before upgrading;
Auth rejects the removed flag at startup. Ensure management clients have the
required scopes and obtain new tokens before upgrading. Existing tokens are not
rewritten. This change applies to Auth only; other services retain their own
scope-checking configuration.

## Token signing key

The `auth serve` command requires `--signing-key`. Pass a newly generated RSA private key as PEM text. The key must use the PKCS#1 encoding produced by `openssl genrsa` or `openssl genpkey -traditional`.

Generate a key and inject its contents through the deployment secret mechanism:

```sh
openssl genrsa -traditional -out auth-signing-key.pem 4096
auth serve --signing-key "$(cat auth-signing-key.pem)" # also requires CRYPTO_KEY; see below
```

Do not store the private key in the repository, a container image, or command output. The service refuses to start when the flag is empty, the PEM cannot be decoded, the key is not a PKCS#1 RSA private key, or the key matches the compromised legacy key removed from this repository.

When delegated OIDC is enabled, Auth loads the provider's JWKS at startup and caches it. During JWT bearer token exchange, an assertion signed with an unknown `kid` triggers a single coalesced JWKS refresh; concurrent requests wait for the same refresh. This allows external OIDC signing-key rotation without restarting Auth.

The service derives the JSON Web Key Set (JWKS) `kid` from the SHA-256 digest of the public key. Replacing the private key therefore publishes a new `kid` and invalidates tokens signed with the previous key. Services that validate Auth tokens must refresh their JWKS cache after a rotation.

## Migration from the embedded key

Deployments that relied on the former embedded default must inject a new key before upgrading. Tokens signed by the former key must no longer be accepted. Coordinate the Auth rollout with downstream token validators so they load the new JWKS before normal traffic resumes.

## Token revocation

Send an `application/x-www-form-urlencoded` POST to `/revoke` with the token in the `token` parameter and the authentication required for its issuing client. Confidential clients must authenticate, for example with HTTP Basic client credentials. Only the issuing client can revoke the token; a request from another client returns `401 invalid_client` and leaves the token intact.

The `token_type_hint` parameter is optional. Auth ignores it and first looks for a refresh token, then resolves an access token. This follows [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1) and permits revocation with an absent, incorrect or unknown hint. Successful revocation returns HTTP `200`. An unknown or already revoked token also returns `200`.

Revoking an access token deletes its stored token record. Its refresh token, if present, remains valid. Revoking a refresh token deletes both that refresh token and all stored access tokens derived from it. A later `grant_type=refresh_token` request with the revoked refresh token returns `400 invalid_grant`. Tokens associated with a different refresh token remain intact.

Auth endpoints that consult stored access tokens, such as `/userinfo`, reject them after deletion. Revocation does not invalidate a JWT's signature. A consumer that checks only the signature and expiry can continue accepting a revoked access token until it expires; immediate revocation requires the consumer to check token state as well.

New JWT bearer access tokens retain the identity of the authenticated issuing client. Assertion claims such as `client_id` and `azp` do not select the token owner. JWT bearer tokens issued before this fix may have an empty stored `ApplicationID`. Auth does not backfill these records from assertion claims: the client's `/revoke` request cannot revoke them, and they remain subject to their original expiry.

## Client-credentials token introspection

A confidential client can obtain an access token through the `client_credentials` grant at `/oauth/token`. It can then authenticate with its client ID and secret at `/oauth/introspect` to inspect that token.

A valid machine token now returns `active: true`, its issuing `client_id`, and its granted scopes in the space-delimited `scope` field. For example:

```json
{"active":true,"scope":"auth:read auth:write","client_id":"machine"}
```

Previously, introspection attempted to load a user for every token and returned `{"active":false}` for machine tokens because they have no user. Integrations that use introspection can now accept these valid tokens. The change does not grant additional scopes.

Machine-token responses contain no user subject (`sub`), email, or other user claims, even when the token includes `openid` or `email` scopes. Tokens associated with a user retain their existing scope-dependent user claims.

The access restrictions are unchanged. The requesting client must authenticate and must either be in the token's audience or have `trusted: true`. A client can introspect its own token without being trusted. A trusted client inspecting another client's token receives that token's issuing `client_id`, not its own ID. This behavior does not allow an untrusted client outside the audience to inspect the token.

## OIDC encryption key

`auth serve` requires `--crypto-key` or `CRYPTO_KEY`, with no default. An explicit
flag takes precedence over the environment variable, as with other service flags.
Provide at least 32 bytes of high-entropy secret material, excluding surrounding
whitespace from the minimum length. Auth derives the 32-byte AES key with SHA-256
of the exact supplied bytes; hashing does not increase the secret's entropy.
Missing, short, or whitespace-only values fail startup before storage or listeners
start. The provider also rejects zero, empty-hash, and legacy public keys.

This is a dedicated symmetric OIDC key. It is separate from `SIGNING_KEY`, the RSA
private key used for JWT signatures. Provision it through the deployment secret
mechanism. Keep the same value across replicas and restarts, and use separate
values for separate environments. Do not commit it, print it, generate it at
process startup, or generate a new value on each chart render.

### Migration and rollout prerequisites

Before deploying this version, the deployment owner must provision a stable Auth
secret and wire it to `CRYPTO_KEY` (or `--crypto-key`) for every replica. This PR
changes Auth only; Helm and infrastructure must supply that secret separately.
The enforcing binary will not start without it. Earlier binaries do not support
the new flag, so do not pass `--crypto-key` to an earlier binary.

The previous binary always uses the public `SHA-256("test")` key. A mixed rollout
therefore cannot share opaque artifacts between old and new replicas. Plan a
coordinated cutover and a window to drain in-flight OIDC operations. There is no
legacy-key fallback. Rolling back to the old binary restores the vulnerability
and loses compatibility with opaque artifacts encrypted under the new key.
Require a security decision before rollback; prefer a forward fix with the same
configured secret.

Changing the key invalidates old opaque access-token envelopes at introspection,
userinfo, and revocation. Clients should obtain new tokens and retry interrupted
login flows. JWT signatures and expiry remain unchanged when `SIGNING_KEY` stays
the same, including the intentional validity of issued JWTs after client deletion
or revocation. Refresh-token UUIDs are stored independently and are not rotated
by this setting.

Authorization codes use the same encryption key when created, but this service
redeems them by exact stored ciphertext rather than decryption. Rotation alone
does not invalidate an already stored code. Auth does not currently enforce a
local expiration when it looks up a code by ciphertext, so waiting during the
cutover is not an invalidation mechanism. If the rollout must invalidate every
artifact created under the old key, the deployment owner must arrange an
explicit purge of outstanding authorization requests as a separate, reviewed
operation. New codes use the configured secret. The key change itself requires
no database migration.

Go callers of `oidc.Module` and `oidc.NewOpenIDProvider` must now supply an explicit
`[32]byte` crypto key. The HTTP API is unchanged.
