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

This phase changes token issuance only. `--auth-check-scopes` remains optional
and defaults to `false`; explicit `false` and `true` remain supported. Auth does
not start enforcing scopes by default, and this change does not enable scope
checks in other services. Deployments must review client scopes and token
consumers before enabling enforcement in a later rollout phase.

## Token signing key

The `auth serve` command requires `--signing-key`. Pass a newly generated RSA private key as PEM text. The key must use the PKCS#1 encoding produced by `openssl genrsa` or `openssl genpkey -traditional`.

Generate a key and inject its contents through the deployment secret mechanism:

```sh
openssl genrsa -traditional -out auth-signing-key.pem 4096
auth serve --signing-key "$(cat auth-signing-key.pem)"
```

Do not store the private key in the repository, a container image, or command output. The service refuses to start when the flag is empty, the PEM cannot be decoded, the key is not a PKCS#1 RSA private key, or the key matches the compromised legacy key removed from this repository.

When delegated OIDC is enabled, Auth loads the provider's JWKS at startup and caches it. During JWT bearer token exchange, an assertion signed with an unknown `kid` triggers a single coalesced JWKS refresh; concurrent requests wait for the same refresh. This allows external OIDC signing-key rotation without restarting Auth.

The service derives the JSON Web Key Set (JWKS) `kid` from the SHA-256 digest of the public key. Replacing the private key therefore publishes a new `kid` and invalidates tokens signed with the previous key. Services that validate Auth tokens must refresh their JWKS cache after a rotation.

## Migration from the embedded key

Deployments that relied on the former embedded default must inject a new key before upgrading. Tokens signed by the former key must no longer be accepted. Coordinate the Auth rollout with downstream token validators so they load the new JWKS before normal traffic resumes.

## Client-credentials token introspection

A confidential client can obtain an access token through the `client_credentials` grant at `/oauth/token`. It can then authenticate with its client ID and secret at `/oauth/introspect` to inspect that token.

A valid machine token now returns `active: true`, its issuing `client_id`, and its granted scopes in the space-delimited `scope` field. For example:

```json
{"active":true,"scope":"auth:read auth:write","client_id":"machine"}
```

Previously, introspection attempted to load a user for every token and returned `{"active":false}` for machine tokens because they have no user. Integrations that use introspection can now accept these valid tokens. The change does not grant additional scopes.

Machine-token responses contain no user subject (`sub`), email, or other user claims, even when the token includes `openid` or `email` scopes. Tokens associated with a user retain their existing scope-dependent user claims.

The access restrictions are unchanged. The requesting client must authenticate and must either be in the token's audience or have `trusted: true`. A client can introspect its own token without being trusted. A trusted client inspecting another client's token receives that token's issuing `client_id`, not its own ID. This behavior does not allow an untrusted client outside the audience to inspect the token.
