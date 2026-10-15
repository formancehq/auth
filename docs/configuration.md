# Configuration

## Scope rollout: token issuance

For `client_credentials`, omitting the `scope` parameter grants the scopes
configured on the authenticated client. This default applies to both database
clients and static clients. It lets existing callers receive their configured
scopes without changing their token request during the first rollout phase.

When `scope` is present, Auth grants only the intersection of requested and
configured scopes. An explicitly empty `scope` grants no scopes. A client with
no configured scopes receives no scopes, including when it requests privileged
scopes. Changing client configuration affects newly issued tokens; existing
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

The service derives the JSON Web Key Set (JWKS) `kid` from the SHA-256 digest of the public key. Replacing the private key therefore publishes a new `kid` and invalidates tokens signed with the previous key. Services that validate Auth tokens must refresh their JWKS cache after a rotation.

## Migration from the embedded key

Deployments that relied on the former embedded default must inject a new key before upgrading. Tokens signed by the former key must no longer be accepted. Coordinate the Auth rollout with downstream token validators so they load the new JWKS before normal traffic resumes.
