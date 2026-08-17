package pki

import (
	"context"
	"log/slog"
	"sort"

	"github.com/certpilot/certpilot/core/store"
)

// ChainNode represents a node in the CA hierarchy tree.
type ChainNode struct {
	Authority *store.CAAuthority `json:"authority"`
	Children  []*ChainNode       `json:"children"`
	// Depth is the number of issuing steps from the root of this node's chain.
	// A root is 0.
	Depth int `json:"depth"`
	// Detached marks a CA that could not be placed under its stated parent.
	// It is still returned, at the top level, because a CA that vanishes from
	// the hierarchy view is the one nobody notices expiring.
	Detached bool `json:"detached,omitempty"`
	// DetachedReason explains the placement in words an operator can act on.
	DetachedReason string `json:"detached_reason,omitempty"`
}

// ChainResolver builds hierarchy trees from flat CA authority lists.
type ChainResolver struct {
	store store.Store
}

// NewChainResolver creates a new trust chain resolver.
func NewChainResolver(s store.Store) *ChainResolver {
	return &ChainResolver{store: s}
}

// BuildHierarchyTree returns the root CA nodes with their children recursively
// attached.
func (r *ChainResolver) BuildHierarchyTree(ctx context.Context) ([]*ChainNode, error) {
	cas, err := r.store.ListCAAuthorities(ctx, store.CAFilter{})
	if err != nil {
		return nil, err
	}
	return BuildTree(cas), nil
}

// BuildTree assembles a hierarchy from a flat list of authorities.
//
// Separated from the store lookup so the placement rules can be tested directly:
// the interesting cases here are malformed hierarchies, and constructing those
// through a store is far more work than constructing the list.
//
// Three properties this guarantees, none of which the first implementation had:
//
//   - **Depth does not depend on the order of the input.** Depth used to be
//     assigned while walking the input, as `parent.Depth + 1`, so a grandchild
//     seen before its parent read the parent's not-yet-assigned zero and
//     reported depth 1 instead of 2. Depth is now assigned by descending from
//     the roots, where a parent is by construction already placed.
//   - **The result is acyclic.** A CA naming itself, or a pair naming each
//     other, previously produced a structure with a loop in it. `json.Marshal`
//     refuses to encode that ("encountered a cycle"), and Gin has already sent
//     the 200 and the content type by the time the encode fails — so one bad
//     `parent_ca_id` made the hierarchy endpoint return a successful, empty
//     response for the entire estate.
//   - **Every CA appears exactly once.** Members of a loop were previously
//     unreachable from any root and so were silently absent from the response.
//     They now surface at the top level, flagged, which is the whole point of a
//     monitoring tool: show the operator the thing that is wrong rather than
//     quietly dropping it.
func BuildTree(cas []*store.CAAuthority) []*ChainNode {
	nodes := make(map[string]*ChainNode, len(cas))
	// Input order is preserved separately: ranging over the map would make the
	// output order — and previously the depths — vary between identical calls.
	ordered := make([]*ChainNode, 0, len(cas))

	for _, ca := range cas {
		if ca == nil {
			continue
		}
		node := &ChainNode{Authority: ca, Children: make([]*ChainNode, 0)}
		nodes[ca.ID] = node
		ordered = append(ordered, node)
	}

	childrenOf := make(map[string][]*ChainNode, len(nodes))
	roots := make([]*ChainNode, 0)

	for _, node := range ordered {
		parentID := ""
		if p := node.Authority.ParentCAID; p != nil {
			parentID = *p
		}

		switch {
		case parentID == "":
			roots = append(roots, node)

		case parentID == node.Authority.ID:
			detach(node, "this CA is recorded as its own issuer")
			roots = append(roots, node)

		case nodes[parentID] == nil:
			// Common and legitimate: an intermediate imported without its root,
			// or a root held offline in a safe. Worth showing, not warning about.
			node.Detached = true
			node.DetachedReason = "its issuing CA is not registered in CertPilot"
			roots = append(roots, node)

		default:
			childrenOf[parentID] = append(childrenOf[parentID], node)
		}
	}

	// Descend from the roots. Anything a descent never reaches is in a loop.
	placed := make(map[string]bool, len(nodes))
	stack := make([]*ChainNode, 0, len(roots))
	sortNodes(roots)
	stack = append(stack, roots...)

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if placed[node.Authority.ID] {
			continue
		}
		placed[node.Authority.ID] = true

		children := childrenOf[node.Authority.ID]
		sortNodes(children)
		for _, child := range children {
			if placed[child.Authority.ID] {
				continue
			}
			child.Depth = node.Depth + 1
			node.Children = append(node.Children, child)
			stack = append(stack, child)
		}
	}

	// Whatever is left names a parent that names it back, directly or through a
	// longer ring. Its Children were never populated, so promoting it to the top
	// level breaks the cycle rather than reproducing it.
	for _, node := range ordered {
		if placed[node.Authority.ID] {
			continue
		}
		detach(node, "its issuer chain forms a loop, so it has no root")
		node.Depth = 0
		placed[node.Authority.ID] = true
		roots = append(roots, node)
	}

	sortNodes(roots)
	return roots
}

// detach flags a node and logs it. Reserved for states that mean the recorded
// hierarchy is wrong, as opposed to merely incomplete — those are an operator's
// problem to fix and should not be discoverable only by reading the API output.
func detach(node *ChainNode, reason string) {
	node.Detached = true
	node.DetachedReason = reason
	slog.Warn("CA hierarchy is malformed",
		"ca_id", node.Authority.ID, "ca_name", node.Authority.Name, "reason", reason)
}

// sortNodes gives the tree a stable order: name first, ID to break ties.
//
// Without it the sibling order came from map iteration and changed on every
// request, which makes a hierarchy view on a wall display shuffle itself for no
// reason and makes any diff of the API response useless.
func sortNodes(nodes []*ChainNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i].Authority, nodes[j].Authority
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
}
