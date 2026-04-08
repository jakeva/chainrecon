package analyzer

import "strings"

// jsExtensions is the set of JavaScript and TypeScript file extensions that
// code analyzers should inspect.
var jsExtensions = map[string]bool{
	".js":  true,
	".mjs": true,
	".cjs": true,
	".ts":  true,
}

// isJSFile reports whether the given file path has a JavaScript or TypeScript
// extension (.js, .mjs, .cjs, .ts).
func isJSFile(path string) bool {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return false
	}
	return jsExtensions[path[idx:]]
}
