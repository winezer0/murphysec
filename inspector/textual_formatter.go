package inspector

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/murphysecurity/murphysec/env"
	"github.com/murphysecurity/murphysec/model"
	"github.com/murphysecurity/murphysec/utils/must"
)

type DependencyGraph struct {
	nodes     []model.Component
	nodeIndex map[model.Component]int
	edges     map[[2]int]struct{}
}

func (d *DependencyGraph) indexOf(component model.Component) int {
	if i, ok := d.nodeIndex[component]; ok {
		return i
	}
	i := len(d.nodes)
	d.nodeIndex[component] = i
	d.nodes = append(d.nodes, component)
	return i
}

func (d *DependencyGraph) putEdge(from, to model.Component) {
	var fromIndex = d.indexOf(from)
	var toIndex = d.indexOf(to)
	d.edges[[2]int{fromIndex, toIndex}] = struct{}{}
}

func (d *DependencyGraph) _visit(parent model.Component, dep model.DependencyItem) {
	d.putEdge(parent, dep.Component)
	for _, it := range dep.Dependencies {
		d._visit(it.Component, it)
	}
}

// BuildSpdx renders the dependency graph as an SPDX 2.3 JSON document.
func BuildSpdx(task *model.ScanTask) []byte {
	return BuildSpdxWithNotes(task, nil)
}

// BuildSpdxWithNotes is BuildSpdx plus document-level annotations.
//
// SPDX has no field for "this scan was degraded", but that is exactly the kind
// of caveat a consumer of an SBOM needs: a graph produced by the fallback
// resolver is incomplete, and an incomplete graph under-reports
// vulnerabilities. Notes are written as document annotations so they survive
// alongside the data instead of being lost on stderr.
func BuildSpdxWithNotes(task *model.ScanTask, notes []string) []byte {
	var g = DependencyGraph{
		nodes:     nil,
		nodeIndex: make(map[model.Component]int),
		edges:     make(map[[2]int]struct{}),
	}
	for _, module := range task.Modules {
		for _, it := range module.Dependencies {
			g.indexOf(it.Component)
			for _, dependency := range it.Dependencies {
				g._visit(it.Component, dependency)
			}
		}
	}

	var packages = make([]any, 0)
	for i, node := range g.nodes {
		var m = map[string]any{
			"SPDXID":       fmt.Sprint("SPDXRef-package-", i),
			"name":         componentName(node),
			"versionInfo":  node.CompVersion,
			"fileAnalyzed": false,
		}
		var externalRefs = make([]map[string]any, 0)
		// A native package-manager reference is kept where one exists, but the
		// purl is what actually matters downstream: SBOM consumers such as
		// osv-scanner identify a package by its purl and silently drop
		// packages that have none.
		switch node.Ecosystem {
		case "maven":
			externalRefs = append(externalRefs, map[string]any{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator":  node.CompName + ":" + node.CompVersion,
				"referenceType":     "maven-central",
			})
		case "npm":
			externalRefs = append(externalRefs, map[string]any{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator":  node.CompName + "@" + node.CompVersion,
				"referenceType":     "npm",
			})
		}
		if purl := componentPURL(node); purl != "" {
			externalRefs = append(externalRefs, map[string]any{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator":  purl,
				"referenceType":     "purl",
			})
		}
		externalRefs = append(externalRefs, map[string]any{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceLocator":  base64.StdEncoding.EncodeToString(must.A(json.Marshal(node))),
			"referenceType":     "murphyjson",
		})
		if len(externalRefs) != 0 {
			m["externalRefs"] = externalRefs
		}
		packages = append(packages, m)
	}
	var relationships = make([]any, 0)
	for ints := range g.edges {
		var from = ints[0]
		var to = ints[1]
		relationships = append(relationships, map[string]any{
			"relationshipType":   "DEPENDS_ON",
			"spdxElementId":      fmt.Sprint("SPDXRef-package-", from),
			"relatedSpdxElement": fmt.Sprint("SPDXRef-package-", to),
		})
	}
	var spdx = map[string]any{
		"SPDXID":      "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"creationInfo": map[string]any{
			"created":  time.Now().UTC().Format(time.RFC3339),
			"creators": []string{"Tool: murphysec-cli"},
		},
		"name":        env.SpdxName,
		"dataLicense": "CC0-1.0",
		// documentNamespace is required by SPDX 2.3 and must be unique per
		// document; without it a strict validator rejects the file even though
		// tolerant consumers such as osv-scanner accept it.
		"documentNamespace": fmt.Sprintf("https://murphysec.com/spdx/%s-%d", env.SpdxName, time.Now().UnixNano()),
		"packages":          packages,
		"relationships":     relationships,
	}
	if len(packages) > 0 {
		// documentDescribes names the element the document is about. The first
		// package is the closest equivalent of a subject in a flat component
		// list; the relationships still carry the full graph.
		spdx["documentDescribes"] = []string{"SPDXRef-package-0"}
	}
	if len(notes) > 0 {
		spdx["annotations"] = []map[string]any{{
			"annotationDate": time.Now().UTC().Format(time.RFC3339),
			"annotationType": "OTHER",
			"annotator":      "Tool: murphysec-cli",
			"comment": "scan degraded (" + strings.Join(notes, ", ") +
				"): the dependency graph may be incomplete, so vulnerabilities may be under-reported",
		}}
	}
	data, e := json.MarshalIndent(spdx, "", "  ")
	if e != nil {
		panic("marshal spdx failed: " + e.Error())
	}
	return data
}

// purlTypeByEcosystem maps a murphysec ecosystem identifier onto a package-url
// type (https://github.com/package-url/purl-spec).
//
// Ecosystems absent from the table have no purl type. Their packages are still
// exported, just without a purl, and an SBOM consumer cannot identify them:
// osv-scanner reports "Filtered N local/unscannable package/s" and drops them
// without failing, so a missing purl is a silent loss of coverage rather than
// a visible error.
var purlTypeByEcosystem = map[string]string{
	"maven":     "maven",
	"npm":       "npm",
	"pypi":      "pypi",
	"go":        "golang",
	"nuget":     "nuget",
	"composer":  "composer",
	"cargo":     "cargo",
	"bundler":   "gem",
	"pubspec":   "pub",
	"conan":     "conan",
	"cocoapods": "cocoapods",
	"luarocks":  "luarocks",
	"hex":       "hex",
}

// componentPURL builds the package URL of a component, or "" when its
// ecosystem has no purl type.
func componentPURL(node model.Component) string {
	typ, ok := purlTypeByEcosystem[strings.ToLower(node.Ecosystem)]
	if !ok || typ == "" || node.CompName == "" {
		return ""
	}

	var namespace, name string
	switch typ {
	case "maven":
		// Maven coordinates are "groupId:artifactId". A purl expresses that as
		// namespace/name, so the colon becomes a slash.
		group, artifact, found := strings.Cut(node.CompName, ":")
		if !found {
			name = url.PathEscape(node.CompName)
			break
		}
		namespace = url.PathEscape(group)
		name = url.PathEscape(artifact)
	case "npm":
		// Scoped packages are "@scope/name". The purl spec wants the scope as a
		// namespace with the leading '@' percent-encoded.
		if strings.HasPrefix(node.CompName, "@") {
			scope, pkg, found := strings.Cut(strings.TrimPrefix(node.CompName, "@"), "/")
			if found {
				namespace = "%40" + url.PathEscape(scope)
				name = url.PathEscape(pkg)
				break
			}
		}
		name = url.PathEscape(node.CompName)
	default:
		// Multi-segment names such as Go module paths keep their slashes: the
		// last segment becomes the name and the rest the namespace only for
		// some types, so the whole path is escaped segment by segment.
		name = escapePURLPath(node.CompName)
	}

	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteString("/")
	if namespace != "" {
		b.WriteString(namespace)
		b.WriteString("/")
	}
	b.WriteString(name)
	if node.CompVersion != "" {
		b.WriteString("@")
		b.WriteString(escapePURLPath(node.CompVersion))
	}
	return b.String()
}

// escapePURLPath percent-encodes each slash-separated segment of a purl,
// leaving the separators intact.
func escapePURLPath(s string) string {
	parts := strings.Split(s, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// componentName is the package name as the ecosystem spells it. Maven carries
// "groupId:artifactId" in CompName; SPDX wants the name on its own, with the
// group expressed through the purl namespace instead.
func componentName(node model.Component) string {
	if strings.EqualFold(node.Ecosystem, "maven") {
		if _, artifact, found := strings.Cut(node.CompName, ":"); found {
			return artifact
		}
	}
	return node.CompName
}
