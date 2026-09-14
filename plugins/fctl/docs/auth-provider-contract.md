# `auth.stack` provider contract

The portable component exposes one Auth provider capability: `auth.stack`.
It implements the final client-credentials flow against the public fctl broker
ABI without receiving an endpoint, client identifier, client secret, bearer
token, or authorization header.

## Authority boundary

The host supplies an optional `CredentialSlot` with each `AuthRequest`. This
provider accepts a request only when:

- the requested capability is exactly `auth.stack`;
- the slot is present and passes the SDK's complete authority validation;
- exactly one operation is requested;
- the slot names this provider and this provider version;
- the host exposes the directional `ClientCredentialsAuthHost` extension.

An absent slot identifies an OIDC-only or discovery flow and is not applicable
to this provider. Multi-operation flows, mismatched authority, malformed scope
sets, and older hosts fail with `operation_not_permitted` before broker access.

## Broker sequence

For an admitted request, the provider performs exactly two operations:

1. `AuthorizeClientCredentials` receives an owned copy of the host-validated
   slot and an intent containing the request service and the slot's exact scope
   set. A present empty scope set stays present and empty.
2. `BindCredential` receives another owned copy of that slot, the opaque handle
   returned by authorization, and the single requested operation.

Both broker responses must contain a non-empty opaque value. An empty handle is
rejected before binding, and an empty binding is rejected before a result can
escape the provider. The returned credential binding is converted to the public
opaque service binding.

The provider does not call the generic OIDC, refresh, exchange, load,
invalidate, or bind methods and does not infer scopes or audience. The current
directional ABI keeps generation revalidation and capability-scoped
client-credentials invalidation host-owned; it exposes no provider-callable
directional invalidation operation.

The component descriptor declares the auth facet with protocol version `1` and
the single `auth.stack` capability. Repository-local lifecycle tests verify
that this descriptor is exported; live CLI-host and browser-host exchanges are
separate external acceptance evidence.
