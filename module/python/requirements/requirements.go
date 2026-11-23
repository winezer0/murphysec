package requirements

// Parse maps requirement declarations to the scan version selected by the
// Python version policy. Entries without a usable version have an empty value.
func Parse(data string) map[string]string {
	result := make(map[string]string)
	for _, item := range parseDeclarations(data) {
		result[item.name] = item.version
	}
	return result
}

// Declarations returns original manifest constraints before scan-version selection.
func Declarations(data string) map[string]string {
	result := make(map[string]string)
	for _, item := range parseDeclarations(data) {
		result[item.name] = item.constraint
	}
	return result
}
