package core

import (
	"sort"
	"strconv"
	"strings"

	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

const schemaDialect = "https://json-schema.org/draft/2020-12/schema"

var objectSchema = []byte(`{"$schema":"` + schemaDialect + `","type":"object"}`)
var collectionSchema = []byte(`{"$schema":"` + schemaDialect + `","type":"array"}`)

func buildInputSchema(arguments []sdk.Argument, flags []sdk.Flag) []byte {
	type field struct {
		kind            string
		array, required bool
	}
	fields := map[string]field{}
	for _, a := range arguments {
		fields[a.Name] = field{kind: "string", array: a.Repeated, required: a.Required}
	}
	for _, f := range flags {
		kind := "string"
		if f.Type == sdk.FlagBool {
			kind = "boolean"
		}
		fields[f.Name] = field{kind: kind, array: f.Type == sdk.FlagStringArray, required: f.Required}
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	properties, required := make([]string, 0, len(names)), []string{}
	for _, name := range names {
		value := fields[name]
		property := `{"type":` + strconv.Quote(value.kind)
		if value.array {
			property = `{"type":"array","items":{"type":` + strconv.Quote(value.kind) + `}`
		}
		property += `}`
		properties = append(properties, strconv.Quote(name)+":"+property)
		if value.required {
			required = append(required, strconv.Quote(name))
		}
	}
	out := `{"$schema":"` + schemaDialect + `","type":"object","properties":{` + strings.Join(properties, ",") + `}`
	if len(required) > 0 {
		out += `,"required":[` + strings.Join(required, ",") + `]`
	}
	out += `,"additionalProperties":false}`
	return []byte(out)
}
