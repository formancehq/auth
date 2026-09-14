// Package audit extracts a deterministic, auditable inventory of the Auth HTTP
// surface from this repository's own OpenAPI document, and pins the legacy fctl
// command baseline it has to be measured against.
//
// The package is deliberately read-only and dependency-light. It keeps the
// source inventory independently reproducible while the sibling packages
// implement the generated-client adapter, plugin entry point, and auth facet.
//
// The OpenAPI document is authoritative for operation semantics. The adapter's
// generated-client method mappings are separately proven by compilation and
// tests in the plugin module.
package audit

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Tag is the single tag every operation in the Auth document carries. Unlike
// the Payments document there is no second API generation to partition, so the
// loader asserts the tag instead of switching on it.
const Tag = "auth.v1"

// Parameter is one resolved OpenAPI parameter of an operation.
type Parameter struct {
	Name     string `json:"name" yaml:"name"`
	In       string `json:"in" yaml:"in"`
	Required bool   `json:"required" yaml:"required"`
}

// Operation is one (method, path) OpenAPI operation of the Auth API.
//
// Every field is read from the document; nothing is inferred. In particular
// Scopes is nil when the operation declares no security block at all, which is
// a different, weaker fact than an empty declared scope array.
type Operation struct {
	OperationID string      `json:"operationId"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Tag         string      `json:"tag"`
	Summary     string      `json:"summary"`
	Deprecated  bool        `json:"deprecated"`
	HasSecurity bool        `json:"hasSecurity"`
	Scopes      []string    `json:"scopes"`
	Parameters  []Parameter `json:"parameters"`
	RequestBody string      `json:"requestBody"`
	SuccessCode string      `json:"successCode"`
	SuccessBody string      `json:"successBody"`
}

// HasRequestBody reports whether the operation declares a JSON request body.
func (o Operation) HasRequestBody() bool { return o.RequestBody != "" }

// HasResponseBody reports whether the operation declares a JSON success schema.
// A false result on a 2xx is a real fact about the document, not an omission:
// the two 204 deletes and getOIDCWellKnowns all declare no schema.
func (o Operation) HasResponseBody() bool { return o.SuccessBody != "" }

// Mutating reports whether the operation uses a state-changing HTTP method.
func (o Operation) Mutating() bool {
	switch o.Method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// Paginated reports whether the operation declares any pagination parameter.
//
// It is always false for the current Auth document: neither listClients nor
// listUsers declares a cursor, page-size, limit, or offset parameter, and both
// return an unbounded `data` array. That is recorded as a divergence rather
// than assumed away; see blockers.go, divergence `no-pagination`.
func (o Operation) Paginated() bool {
	for _, p := range o.Parameters {
		switch p.Name {
		case "cursor", "pageSize", "limit", "offset", "after", "page":
			return true
		}
	}
	return false
}

// yaml shapes: only the fields this audit reads are modelled.

type yamlSchema struct {
	Ref string `yaml:"$ref"`
}

type yamlMediaType struct {
	Schema yamlSchema `yaml:"schema"`
}

type yamlBody struct {
	Content map[string]yamlMediaType `yaml:"content"`
}

type yamlResponse struct {
	Description string                   `yaml:"description"`
	Content     map[string]yamlMediaType `yaml:"content"`
}

type yamlOperation struct {
	OperationID string                  `yaml:"operationId"`
	Summary     string                  `yaml:"summary"`
	Tags        []string                `yaml:"tags"`
	Deprecated  bool                    `yaml:"deprecated"`
	Parameters  []Parameter             `yaml:"parameters"`
	RequestBody *yamlBody               `yaml:"requestBody"`
	Responses   map[string]yamlResponse `yaml:"responses"`
	Security    *[]map[string][]string  `yaml:"security"`
}

type yamlPathItem struct {
	Get     *yamlOperation `yaml:"get"`
	Put     *yamlOperation `yaml:"put"`
	Post    *yamlOperation `yaml:"post"`
	Delete  *yamlOperation `yaml:"delete"`
	Patch   *yamlOperation `yaml:"patch"`
	Head    *yamlOperation `yaml:"head"`
	Options *yamlOperation `yaml:"options"`
	Trace   *yamlOperation `yaml:"trace"`
}

type yamlDocument struct {
	OpenAPI string `yaml:"openapi"`
	Info    struct {
		Title   string `yaml:"title"`
		Version string `yaml:"version"`
	} `yaml:"info"`
	Servers []struct {
		URL string `yaml:"url"`
	} `yaml:"servers"`
	// Paths is decoded as raw nodes because the Auth document places the
	// vendor extension `x-speakeasy-errors` as a sibling of the real path
	// items. Decoding straight into yamlPathItem would silently accept it as
	// a path with no operations; keeping nodes lets the loader reject any
	// non-path key it does not explicitly know about.
	Paths map[string]yaml.Node `yaml:"paths"`
}

// methodsOf returns the path item's declared operations in a fixed method
// order, so extraction output is stable for a given document.
func methodsOf(item yamlPathItem) []struct {
	method string
	op     *yamlOperation
} {
	return []struct {
		method string
		op     *yamlOperation
	}{
		{"GET", item.Get},
		{"PUT", item.Put},
		{"POST", item.Post},
		{"DELETE", item.Delete},
		{"PATCH", item.Patch},
		{"HEAD", item.Head},
		{"OPTIONS", item.Options},
		{"TRACE", item.Trace},
	}
}

// knownPathExtensions are the non-path keys the Auth document is known to
// place under `paths:`. They are skipped rather than parsed. Any other
// non-path key is an error, so a future document change cannot be absorbed
// unnoticed.
var knownPathExtensions = map[string]struct{}{
	"x-speakeasy-errors": {},
}

// successOf picks the operation's single declared 2xx response. More than one
// is an error rather than a silent choice, so the audit cannot quote a success
// code the document does not uniquely define.
func successOf(op *yamlOperation, id string) (code, body string, err error) {
	var codes []string
	for c := range op.Responses {
		if strings.HasPrefix(c, "2") {
			codes = append(codes, c)
		}
	}
	sort.Strings(codes)
	switch len(codes) {
	case 0:
		return "", "", fmt.Errorf("operation %s declares no 2xx response", id)
	case 1:
	default:
		return "", "", fmt.Errorf("operation %s declares %d 2xx responses (%s); the audit models exactly one", id, len(codes), strings.Join(codes, ", "))
	}

	code = codes[0]
	if media, ok := op.Responses[code].Content["application/json"]; ok {
		body = refName(media.Schema.Ref)
	}
	return code, body, nil
}

// refName reduces a local component reference to its schema name. A non-local
// or unexpected reference is returned verbatim so it stays visible in the
// generated artefacts instead of being normalised into something misleading.
func refName(ref string) string {
	const prefix = "#/components/schemas/"
	if strings.HasPrefix(ref, prefix) {
		return strings.TrimPrefix(ref, prefix)
	}
	return ref
}

// scopesOf flattens an operation's security requirement into the exact scope
// set the document declares.
//
// The Auth document uses exactly one scheme (`Authorization`) with exactly one
// requirement object per operation. Anything else is an error: RFC 0014
// requires a canonical exact scope set, and an OR of alternative requirements
// would not be one.
func scopesOf(op *yamlOperation, id string) (hasSecurity bool, scopes []string, err error) {
	if op.Security == nil {
		return false, nil, nil
	}
	reqs := *op.Security
	if len(reqs) != 1 {
		return true, nil, fmt.Errorf("operation %s declares %d security requirement objects; the audit models exactly one exact scope set", id, len(reqs))
	}
	if len(reqs[0]) != 1 {
		return true, nil, fmt.Errorf("operation %s declares %d security schemes in one requirement; the audit models exactly one", id, len(reqs[0]))
	}
	for name, declared := range reqs[0] {
		if name != SecurityScheme {
			return true, nil, fmt.Errorf("operation %s declares unknown security scheme %q", id, name)
		}
		scopes = append([]string(nil), declared...)
	}
	sort.Strings(scopes)
	return true, scopes, nil
}

// SecurityScheme is the only security scheme name the Auth document declares.
const SecurityScheme = "Authorization"

// Document is the non-operation metadata the audit reads, kept so the
// generated artefacts can quote the document's own self-description instead of
// a transcribed value.
type Document struct {
	OpenAPI string `json:"openapi"`
	Title   string `json:"title"`
	// Version is `info.version`. It is the document's own version string and
	// is NOT the product major; live product-major evidence is an external
	// acceptance gate.
	Version string `json:"version"`
	// Servers is `servers[].url` verbatim. The Auth document declares a
	// localhost development server, not the stack gateway route; see
	// divergence `localhost-server`.
	Servers []string `json:"servers"`
}

// Load reads the OpenAPI document at path and returns its metadata plus every
// operation, sorted by operationId.
func Load(path string) (Document, []Operation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Document{}, nil, fmt.Errorf("read %s: %w", path, err)
	}

	var doc yamlDocument
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Document{}, nil, fmt.Errorf("parse %s: %w", path, err)
	}

	meta := Document{OpenAPI: doc.OpenAPI, Title: doc.Info.Title, Version: doc.Info.Version}
	for _, s := range doc.Servers {
		meta.Servers = append(meta.Servers, s.URL)
	}

	var paths []string
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var ops []Operation
	for _, path := range paths {
		if !strings.HasPrefix(path, "/") {
			if _, ok := knownPathExtensions[path]; ok {
				continue
			}
			return Document{}, nil, fmt.Errorf("document declares unknown non-path key %q under paths", path)
		}

		node := doc.Paths[path]
		var item yamlPathItem
		if err := node.Decode(&item); err != nil {
			return Document{}, nil, fmt.Errorf("decode path %s: %w", path, err)
		}

		for _, m := range methodsOf(item) {
			if m.op == nil {
				continue
			}
			op := m.op
			if op.OperationID == "" {
				return Document{}, nil, fmt.Errorf("%s %s declares no operationId", m.method, path)
			}
			if len(op.Tags) != 1 {
				return Document{}, nil, fmt.Errorf("operation %s declares %d tags; the audit models exactly one", op.OperationID, len(op.Tags))
			}
			if op.Tags[0] != Tag {
				return Document{}, nil, fmt.Errorf("operation %s carries tag %q, want %q", op.OperationID, op.Tags[0], Tag)
			}

			code, body, err := successOf(op, op.OperationID)
			if err != nil {
				return Document{}, nil, err
			}
			hasSecurity, scopes, err := scopesOf(op, op.OperationID)
			if err != nil {
				return Document{}, nil, err
			}

			var requestBody string
			if op.RequestBody != nil {
				if media, ok := op.RequestBody.Content["application/json"]; ok {
					requestBody = refName(media.Schema.Ref)
				}
			}

			params := append([]Parameter(nil), op.Parameters...)
			sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })

			ops = append(ops, Operation{
				OperationID: op.OperationID,
				Method:      m.method,
				Path:        path,
				Tag:         op.Tags[0],
				Summary:     op.Summary,
				Deprecated:  op.Deprecated,
				HasSecurity: hasSecurity,
				Scopes:      scopes,
				Parameters:  params,
				RequestBody: requestBody,
				SuccessCode: code,
				SuccessBody: body,
			})
		}
	}

	sort.Slice(ops, func(i, j int) bool { return ops[i].OperationID < ops[j].OperationID })
	return meta, ops, nil
}

// Index maps operations by operationId. A shorter result than the input means
// the document declares a duplicate id.
func Index(ops []Operation) map[string]Operation {
	byID := make(map[string]Operation, len(ops))
	for _, op := range ops {
		byID[op.OperationID] = op
	}
	return byID
}
