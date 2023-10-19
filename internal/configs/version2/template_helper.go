package version2

import (
	"fmt"
	"strings"
	"text/template"
)

func headerListToCIMap(headers []Header) map[string]string {
	ret := make(map[string]string)

	for _, header := range headers {
		ret[strings.ToLower(header.Name)] = header.Value
	}

	return ret
}

func hasCIKey(key string, d map[string]string) bool {
	_, ok := d[strings.ToLower(key)]
	return ok
}

// toLower takes a string and make it lowercase.
//
// Example:
//
//	{{ if .SameSite}} samesite={{.SameSite | toLower }}{{ end }}
func toLower(s string) string {
	return strings.ToLower(s)
}

// generateUpstreamBackup takes a backup server name and port,
// and returns a configuration snippet for the 'upstream' directive.
//
// Example:
//
// server backup1.example.com:9090 backup;
func generateUpstreamBackup(name string, port uint16) string {
	if name == "" || port == 0 {
		return ""
	}
	return fmt.Sprintf("server %s:%d backup;", name, port)
}

var helperFunctions = template.FuncMap{
	"headerListToCIMap":      headerListToCIMap,
	"hasCIKey":               hasCIKey,
	"toLower":                toLower,
	"generateUpstreamBackup": generateUpstreamBackup,
}
