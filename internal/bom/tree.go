package bom

import (
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// tree.go turns the flat CycloneDX dependency array into a walkable tree.
//
// The array is a set of edges, which is the right storage shape and the wrong
// reading shape: "what pulls in this vulnerable package" is a question about
// paths, and paths are what a tree makes visible. Both directions are built
// from the same edge set — forward (what does X depend on) and inverted (what
// depends on X), the latter being the one a triage session actually asks.

// TreeNode is one node in a rendered dependency tree.
type TreeNode struct {
	Ref      string      `json:"ref"`
	Name     string      `json:"name"`
	Version  string      `json:"version,omitempty"`
	Purl     string      `json:"purl,omitempty"`
	Depth    int         `json:"depth"`
	Children []*TreeNode `json:"children,omitempty"`
	// Cycle marks a node whose subtree was elided because it repeats an
	// ancestor. Dependency graphs do contain cycles (Go modules and Maven both
	// permit them); eliding and saying so beats either infinite recursion or
	// silently truncating.
	Cycle bool `json:"cycle,omitempty"`
	// Elided marks a node whose children were cut off by the depth limit.
	Elided bool `json:"elided,omitempty"`
}

// TreeOptions controls tree construction.
type TreeOptions struct {
	// Root selects the starting component by purl, bom-ref or name. Empty
	// starts from the document's subject.
	Root string
	// Invert builds the reverse tree: children are the components that depend
	// on the parent.
	Invert bool
	// MaxDepth caps traversal depth. Zero means unlimited.
	MaxDepth int
}

// ErrNoRoot is returned when a tree has no starting point.
type ErrNoRoot struct{ Requested string }

func (e *ErrNoRoot) Error() string {
	if e.Requested != "" {
		return "no component matching " + e.Requested + " in this document"
	}
	return "document has no metadata.component and no --component was given, so there is no root to build a tree from"
}

// BuildTree constructs a dependency tree from a parsed document.
func BuildTree(doc *Document, opts TreeOptions) (*TreeNode, error) {
	if doc == nil || doc.BOM == nil {
		return nil, &ErrNoRoot{Requested: opts.Root}
	}
	bom := doc.BOM

	byRef := componentsByRef(bom)
	edges := adjacency(bom, opts.Invert)

	rootRef := ""
	if opts.Root != "" {
		rootRef = resolveRef(bom, byRef, opts.Root)
		if rootRef == "" {
			return nil, &ErrNoRoot{Requested: opts.Root}
		}
	} else if bom.Metadata != nil && bom.Metadata.Component != nil {
		rootRef = bom.Metadata.Component.BOMRef
	}
	if rootRef == "" {
		return nil, &ErrNoRoot{}
	}

	return walk(rootRef, byRef, edges, opts.MaxDepth, 0, map[string]bool{}), nil
}

// walk builds the subtree rooted at ref.
func walk(ref string, byRef map[string]*cdx.Component, edges map[string][]string, maxDepth, depth int, onPath map[string]bool) *TreeNode {
	node := &TreeNode{Ref: ref, Depth: depth}
	if c := byRef[ref]; c != nil {
		node.Name, node.Version, node.Purl = c.Name, c.Version, c.Purl
	} else {
		// An edge pointing at a ref with no component is a dangling reference,
		// which real documents do contain. Show the ref rather than dropping
		// the branch, so the gap is visible.
		node.Name = ref
	}

	if onPath[ref] {
		node.Cycle = true
		return node
	}
	if maxDepth > 0 && depth >= maxDepth {
		if len(edges[ref]) > 0 {
			node.Elided = true
		}
		return node
	}

	onPath[ref] = true
	defer delete(onPath, ref)

	children := append([]string(nil), edges[ref]...)
	sort.Slice(children, func(i, j int) bool {
		return labelForRef(byRef, children[i]) < labelForRef(byRef, children[j])
	})
	for _, child := range children {
		node.Children = append(node.Children, walk(child, byRef, edges, maxDepth, depth+1, onPath))
	}
	return node
}

// componentsByRef indexes a document's components by bom-ref, including the
// subject, since the subject is the usual tree root and is not in Components.
func componentsByRef(bom *cdx.BOM) map[string]*cdx.Component {
	out := make(map[string]*cdx.Component, len(bom.Components)+1)
	for i := range bom.Components {
		c := &bom.Components[i]
		if c.BOMRef != "" {
			out[c.BOMRef] = c
		}
		if c.Purl != "" {
			if _, ok := out[c.Purl]; !ok {
				out[c.Purl] = c
			}
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if ref := bom.Metadata.Component.BOMRef; ref != "" {
			out[ref] = bom.Metadata.Component
		}
	}
	return out
}

// adjacency flattens the dependency array into a ref → refs map.
func adjacency(bom *cdx.BOM, invert bool) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	add := func(from, to string) {
		key := from + "\x00" + to
		if seen[key] {
			return
		}
		seen[key] = true
		out[from] = append(out[from], to)
	}
	for _, dep := range bom.Dependencies {
		for _, on := range dep.DependsOn {
			if invert {
				add(on, dep.Ref)
			} else {
				add(dep.Ref, on)
			}
		}
	}
	return out
}

// resolveRef finds the bom-ref for a user-supplied component selector.
//
// Exact purl and exact bom-ref first, then exact name, then a case-insensitive
// substring — the last so `bom tree --component lodash` works without the user
// having to type a full purl.
func resolveRef(bom *cdx.BOM, byRef map[string]*cdx.Component, selector string) string {
	if _, ok := byRef[selector]; ok {
		return selector
	}
	lower := strings.ToLower(selector)
	var substringMatch string
	for i := range bom.Components {
		c := &bom.Components[i]
		if c.Purl == selector || c.Name == selector || nameVersion(c) == selector {
			return c.BOMRef
		}
		if substringMatch == "" && strings.Contains(strings.ToLower(c.Name), lower) {
			substringMatch = c.BOMRef
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if bom.Metadata.Component.Name == selector {
			return bom.Metadata.Component.BOMRef
		}
	}
	return substringMatch
}

// labelForRef is the sort key for a child ref.
func labelForRef(byRef map[string]*cdx.Component, ref string) string {
	if c := byRef[ref]; c != nil && c.Name != "" {
		return c.Name
	}
	return ref
}

// Count returns the number of nodes in the tree, cycles counted once.
func (n *TreeNode) Count() int {
	if n == nil {
		return 0
	}
	total := 1
	for _, c := range n.Children {
		total += c.Count()
	}
	return total
}
