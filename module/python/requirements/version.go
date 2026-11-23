package requirements

import (
	"regexp"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

var requirementNamePattern = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[A-Za-z0-9_., -]+\])?`)
var requirementSpecifierPattern = regexp.MustCompile(`^(===|==|>=|<=|!=|>|<)\s*([^\s]+)$`)

type declaration struct {
	name       string
	version    string
	constraint string
}

func parseDeclarations(data string) []declaration {
	var declarations []declaration
	var pending string
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(line)
		continued := strings.HasSuffix(line, "\\")
		pending += strings.TrimSuffix(line, "\\")
		if continued {
			pending += " "
			continue
		}
		if item, ok := parseDeclaration(pending); ok {
			declarations = append(declarations, item)
		}
		pending = ""
	}
	if pending != "" {
		if item, ok := parseDeclaration(pending); ok {
			declarations = append(declarations, item)
		}
	}
	return declarations
}

func parseDeclaration(line string) (declaration, bool) {
	line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
	if index := strings.Index(line, " --"); index >= 0 {
		line = line[:index]
	}
	match := requirementNamePattern.FindStringSubmatch(line)
	if match == nil {
		return declaration{}, false
	}
	specifiers := strings.TrimSpace(line[len(match[0]):])
	if strings.HasPrefix(specifiers, "@") || strings.HasPrefix(specifiers, "://") {
		return declaration{}, false
	}
	return declaration{name: match[1], version: selectVersion(specifiers), constraint: specifiers}, true
}

func selectVersion(specifiers string) string {
	specifiers = strings.TrimSpace(specifiers)
	if specifiers == "" {
		return ""
	}
	if strings.HasPrefix(specifiers, "(") && strings.HasSuffix(specifiers, ")") {
		specifiers = strings.TrimSpace(specifiers[1 : len(specifiers)-1])
	}
	var exact, lower, upper *pep440.Version
	for _, part := range strings.Split(specifiers, ",") {
		match := requirementSpecifierPattern.FindStringSubmatch(strings.TrimSpace(part))
		if match == nil {
			return ""
		}
		rawVersion := strings.Trim(match[2], "'\"")
		if match[1] == "!=" {
			rawVersion = strings.TrimSuffix(rawVersion, ".*")
		}
		value, err := pep440.Parse(rawVersion)
		if err != nil {
			return ""
		}
		switch match[1] {
		case "==", "===":
			if exact != nil && !exact.Equal(value) {
				return ""
			}
			exact = chooseEquivalent(exact, value)
		case ">=":
			if lower == nil || value.GreaterThan(*lower) {
				lower = &value
			} else if value.Equal(*lower) {
				lower = chooseEquivalent(lower, value)
			}
		case "<=":
			if upper == nil || value.LessThan(*upper) {
				upper = &value
			} else if value.Equal(*upper) {
				upper = chooseEquivalent(upper, value)
			}
		}
	}
	if lower != nil && upper != nil && lower.GreaterThan(*upper) {
		return ""
	}
	if exact != nil {
		if (lower != nil && exact.LessThan(*lower)) || (upper != nil && exact.GreaterThan(*upper)) {
			return ""
		}
		return exact.String()
	}
	if lower != nil {
		return lower.String()
	}
	if upper != nil {
		return upper.String()
	}
	return ""
}

func chooseEquivalent(current *pep440.Version, candidate pep440.Version) *pep440.Version {
	if current == nil || candidate.String() < current.String() {
		return &candidate
	}
	return current
}
