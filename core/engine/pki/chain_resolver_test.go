package pki

import (
	"encoding/json"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

// node builds a CA with an optional parent. A nil parent means a root.
func node(id, name string, parent *string) *store.CAAuthority {
	return &store.CAAuthority{ID: id, Name: name, ParentCAID: parent}
}

func ref(s string) *string { return &s }

// find locates a CA anywhere in the tree, so a test can assert on placement
// without hard-coding the path it expects to find it at.
func find(roots []*ChainNode, id string) *ChainNode {
	for _, root := range roots {
		if root.Authority.ID == id {
			return root
		}
		if got := find(root.Children, id); got != nil {
			return got
		}
	}
	return nil
}

func countNodes(roots []*ChainNode) int {
	n := 0
	for _, root := range roots {
		n += 1 + countNodes(root.Children)
	}
	return n
}

// The regression this file mainly exists for. Depth was assigned while ranging
// over the input, so a grandchild that happened to be seen before its parent
// read the parent's unassigned zero and reported depth 1 instead of 2. Because
// the input came from a map range, the same data produced different depths on
// different requests.
func TestDepthDoesNotDependOnInputOrder(t *testing.T) {
	root := node("root", "Corporate Root", nil)
	mid := node("mid", "Corporate Intermediate", ref("root"))
	leaf := node("leaf", "TLS Issuing CA", ref("mid"))

	orders := map[string][]*store.CAAuthority{
		"parents first":  {root, mid, leaf},
		"children first": {leaf, mid, root},
		"interleaved":    {mid, leaf, root},
	}

	for name, cas := range orders {
		t.Run(name, func(t *testing.T) {
			tree := BuildTree(cas)

			if len(tree) != 1 {
				t.Fatalf("got %d roots, want 1 — the chain should collapse to one root", len(tree))
			}
			for id, want := range map[string]int{"root": 0, "mid": 1, "leaf": 2} {
				got := find(tree, id)
				if got == nil {
					t.Fatalf("%s is missing from the tree", id)
				}
				if got.Depth != want {
					t.Errorf("%s depth = %d, want %d", id, got.Depth, want)
				}
				if got.Detached {
					t.Errorf("%s was flagged detached: %s", id, got.DetachedReason)
				}
			}
		})
	}
}

// A loop used to make its members unreachable from any root, so they were absent
// from the response entirely: a CA that exists, is expiring, and does not appear
// on the hierarchy view at all.
func TestCAsInALoopAreStillReturned(t *testing.T) {
	cas := []*store.CAAuthority{
		node("a", "Alpha CA", ref("b")),
		node("b", "Bravo CA", ref("a")),
		node("healthy", "Standalone Root", nil),
	}

	tree := BuildTree(cas)

	if n := countNodes(tree); n != 3 {
		t.Fatalf("tree holds %d CAs, want 3 — none may be dropped", n)
	}
	for _, id := range []string{"a", "b"} {
		got := find(tree, id)
		if got == nil {
			t.Fatalf("%s disappeared from the tree", id)
		}
		if !got.Detached {
			t.Errorf("%s is in a loop but was not flagged detached", id)
		}
		if len(got.Children) != 0 {
			t.Errorf("%s kept %d children, which reintroduces the cycle", id, len(got.Children))
		}
	}
	if find(tree, "healthy").Detached {
		t.Error("an unrelated healthy root was flagged detached")
	}
}

// The availability half of the same bug. A cyclic structure is not merely wrong,
// it is unserialisable: encoding/json rejects it with "encountered a cycle", and
// Gin has already written the 200 and the content type by then — so one bad
// parent_ca_id turned the hierarchy endpoint into a successful empty response
// for every CA in the estate.
func TestTreeIsAlwaysSerialisable(t *testing.T) {
	cases := map[string][]*store.CAAuthority{
		"self-issued": {node("solo", "Ouroboros CA", ref("solo"))},
		"two-cycle": {
			node("a", "Alpha CA", ref("b")),
			node("b", "Bravo CA", ref("a")),
		},
		"three-cycle": {
			node("a", "Alpha CA", ref("c")),
			node("b", "Bravo CA", ref("a")),
			node("c", "Charlie CA", ref("b")),
		},
		"loop hanging off a real root": {
			node("root", "Corporate Root", nil),
			node("x", "Loop One", ref("y")),
			node("y", "Loop Two", ref("x")),
		},
	}

	for name, cas := range cases {
		t.Run(name, func(t *testing.T) {
			// If this recurses forever the test binary dies here, which is the
			// point: it is exactly what the handler did.
			if _, err := json.Marshal(BuildTree(cas)); err != nil {
				t.Fatalf("could not serialise the tree: %v", err)
			}
			if n := countNodes(BuildTree(cas)); n != len(cas) {
				t.Errorf("tree holds %d CAs, want %d", n, len(cas))
			}
		})
	}
}

// An intermediate imported without its root is ordinary — the root is often held
// offline. It belongs at the top level, marked, not hidden and not warned about
// as if it were corruption.
func TestUnknownParentBecomesATopLevelNode(t *testing.T) {
	tree := BuildTree([]*store.CAAuthority{
		node("mid", "Corporate Intermediate", ref("root-held-offline")),
		node("leaf", "TLS Issuing CA", ref("mid")),
	})

	if len(tree) != 1 {
		t.Fatalf("got %d roots, want 1", len(tree))
	}
	if !tree[0].Detached {
		t.Error("an intermediate with an unregistered issuer should be flagged")
	}
	if tree[0].Depth != 0 {
		t.Errorf("detached root depth = %d, want 0", tree[0].Depth)
	}
	// The subtree below it still has to be intact, or the certificates it issued
	// lose their context too.
	leaf := find(tree, "leaf")
	if leaf == nil || leaf.Depth != 1 {
		t.Fatalf("leaf = %+v, want depth 1 under the detached intermediate", leaf)
	}
}

// A wall display re-renders this on every poll. Sibling order used to come from
// map iteration, so the hierarchy reshuffled itself between identical requests.
func TestOrderIsStableAcrossCalls(t *testing.T) {
	cas := []*store.CAAuthority{
		node("r2", "Beta Root", nil),
		node("r1", "Alpha Root", nil),
		node("c3", "Zulu Issuing", ref("r1")),
		node("c1", "Delta Issuing", ref("r1")),
		node("c2", "Mike Issuing", ref("r1")),
	}

	flatten := func(roots []*ChainNode) []string {
		var out []string
		var walk func([]*ChainNode)
		walk = func(ns []*ChainNode) {
			for _, n := range ns {
				out = append(out, n.Authority.Name)
				walk(n.Children)
			}
		}
		walk(roots)
		return out
	}

	first := flatten(BuildTree(cas))
	want := []string{"Alpha Root", "Delta Issuing", "Mike Issuing", "Zulu Issuing", "Beta Root"}
	if len(first) != len(want) {
		t.Fatalf("got %v, want %v", first, want)
	}
	for i := range want {
		if first[i] != want[i] {
			t.Fatalf("order = %v, want %v", first, want)
		}
	}

	for i := 0; i < 50; i++ {
		again := flatten(BuildTree(cas))
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d reordered the tree: %v then %v", i, first, again)
			}
		}
	}
}

func TestEmptyAndNilInput(t *testing.T) {
	if tree := BuildTree(nil); len(tree) != 0 {
		t.Errorf("nil input produced %d roots", len(tree))
	}
	// A nil element should not take the handler down either.
	if tree := BuildTree([]*store.CAAuthority{nil, node("r", "Root", nil)}); len(tree) != 1 {
		t.Errorf("got %d roots, want 1", len(tree))
	}
}
