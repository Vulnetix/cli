package bom

import (
	"errors"
	"testing"
)

func childNames(n *TreeNode) []string {
	out := make([]string, 0, len(n.Children))
	for _, c := range n.Children {
		out = append(out, c.Name)
	}
	return out
}

func TestBuildTreeForward(t *testing.T) {
	doc := loadFixture(t, "before.cdx.json")
	root, err := BuildTree(doc, TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "payment-service" {
		t.Fatalf("root = %q, want the document subject", root.Name)
	}
	got := childNames(root)
	if len(got) != 2 {
		t.Fatalf("root children = %v, want 2", got)
	}
	// Children are sorted by name so output is stable run to run.
	if got[0] != "express" || got[1] != "lodash" {
		t.Errorf("children = %v, want [express lodash]", got)
	}
	// express → left-pad is a transitive edge and must be walked.
	if names := childNames(root.Children[0]); len(names) != 1 || names[0] != "left-pad" {
		t.Errorf("express children = %v, want [left-pad]", names)
	}
}

// TestBuildTreeInverted covers the direction a triage session actually asks:
// given a vulnerable transitive package, what pulls it in.
func TestBuildTreeInverted(t *testing.T) {
	doc := loadFixture(t, "before.cdx.json")
	root, err := BuildTree(doc, TreeOptions{Root: "left-pad", Invert: true})
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "left-pad" {
		t.Fatalf("root = %q", root.Name)
	}
	if names := childNames(root); len(names) != 1 || names[0] != "express" {
		t.Fatalf("left-pad is pulled in by %v, want [express]", names)
	}
	if names := childNames(root.Children[0]); len(names) != 1 || names[0] != "payment-service" {
		t.Errorf("express is pulled in by %v, want [payment-service]", names)
	}
}

func TestBuildTreeDepthLimit(t *testing.T) {
	doc := loadFixture(t, "before.cdx.json")
	root, err := BuildTree(doc, TreeOptions{MaxDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range root.Children {
		if len(c.Children) != 0 {
			t.Errorf("%s has children past the depth limit", c.Name)
		}
		if c.Name == "express" && !c.Elided {
			t.Error("express has hidden children but is not marked elided")
		}
	}
}

// TestBuildTreeCycle pins that a cycle is marked and stopped rather than
// recursed into. Go modules and Maven both permit cycles, so this is a real
// input, not a hypothetical.
func TestBuildTreeCycle(t *testing.T) {
	input := `{
	  "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
	  "metadata":{"component":{"type":"application","bom-ref":"root","name":"app"}},
	  "components":[
	    {"type":"library","bom-ref":"a","name":"a","version":"1.0.0"},
	    {"type":"library","bom-ref":"b","name":"b","version":"1.0.0"}
	  ],
	  "dependencies":[
	    {"ref":"root","dependsOn":["a"]},
	    {"ref":"a","dependsOn":["b"]},
	    {"ref":"b","dependsOn":["a"]}
	  ]
	}`
	doc, err := LoadBytes([]byte(input), "")
	if err != nil {
		t.Fatal(err)
	}
	root, err := BuildTree(doc, TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// root → a → b → a(cycle)
	a := root.Children[0]
	b := a.Children[0]
	if len(b.Children) != 1 {
		t.Fatalf("b children = %v", childNames(b))
	}
	if !b.Children[0].Cycle {
		t.Error("repeated ancestor not marked as a cycle")
	}
	if len(b.Children[0].Children) != 0 {
		t.Error("cycle node was recursed into")
	}
}

func TestBuildTreeNoRoot(t *testing.T) {
	doc, err := LoadBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), "")
	if err != nil {
		t.Fatal(err)
	}
	var noRoot *ErrNoRoot
	if _, err := BuildTree(doc, TreeOptions{}); !errors.As(err, &noRoot) {
		t.Fatalf("err = %v, want ErrNoRoot", err)
	}
	if _, err := BuildTree(doc, TreeOptions{Root: "nope"}); !errors.As(err, &noRoot) {
		t.Fatalf("err = %v, want ErrNoRoot", err)
	}
}
