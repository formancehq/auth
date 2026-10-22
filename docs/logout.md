# User logout

The `/end_session` endpoint terminates a user session identified by a verified
`id_token_hint` with a nonempty subject. A `client_id` alone does not prove a user
session. Requests without a user subject return HTTP 400 (`invalid_request`)
and do not delete access tokens. This includes hints with an empty subject and
requests without parameters.

Successful logout deletes the access tokens for the hint's user and client.
Tokens for other users or clients and machine tokens for the same client remain
in the registry. The provider preserves the validated logout redirect and `state`.
Refresh-token handling is unchanged.

This registry operation does not make downstream services revoke already-issued
JWTs. Those JWTs remain valid until expiration under the existing contract.
