# fctl SDK projection

`pkg/plugin/` and `wit/` hold a minimal snapshot of the Go SDK and the public
plugin WIT copied from `formancehq/fctl-v2-poc` commit
`e9b1395f46f3100b381dbe00f5213de28e6df0e1`. The included production files are
the union of the fctl packages reached by `go list -deps` for the Auth plugin
in its normal and `fctl_component_guest` builds. Go module manifests and the
public WIT are included in addition to that measured dependency graph; SDK
tests, test data, the internal test protobuf package, the unused product
transports and the TypeScript sources are not consumed and are omitted.

The source repository is private while Auth CI receives a token scoped to the
Auth repository, so no CI job can clone it. Keeping this projection in the Auth
tree makes `just fctl-audit-tidy` and `just fctl-audit-test` self-contained
without adding a cross-repository credential.

`../fctl-sdk.lock.json` is the fail-closed provenance manifest. `bundlePath`
names this directory, and `scripts/with-fctl-sdk.sh` verifies the SDK module
path, the exact Nix content hash of `pkg/plugin`, and the WIT SHA-256 before
any tidy, test, or component build consumes it. Adding, removing, or changing a
file therefore requires an explicit manifest reseal: the hash is taken over
this projection, so `FCTL_SDK_ROOT` must name a source root holding the same
projection rather than a full upstream checkout.
