package pki

import (
	"context"

	"github.com/certpilot/certpilot/core/store"
)

// ChainNode represents a node in the CA hierarchy tree.
type ChainNode struct {
	Authority *store.CAAuthority `json:"authority"`
	Children  []*ChainNode        `json:"children"`
	Depth     int                 `json:"depth"`
}

// ChainResolver builds hierarchy trees from flat CA authority lists.
type ChainResolver struct {
	store store.Store
}

// NewChainResolver creates a new trust chain resolver.
func NewChainResolver(s store.Store) *ChainResolver {
	return &ChainResolver{store: s}
}

// BuildHierarchyTree returns the root CA nodes with their children recursively attached.
func (r *ChainResolver) BuildHierarchyTree(ctx context.Context) ([]*ChainNode, error) {
	cas, err := r.store.ListCAAuthorities(ctx)
	if err != nil {
		return nil, err
	}

	// Index by ID and parent ID
	nodeMap := make(map[string]*ChainNode)
	for _, ca := range cas {
		nodeMap[ca.ID] = &ChainNode{
			Authority: ca,
			Children:  make([]*ChainNode, 0),
		}
	}

	var rootNodes []*ChainNode
	for _, ca := range cas {
		node := nodeMap[ca.ID]
		if ca.ParentCAID != nil && *ca.ParentCAID != "" {
			if parent, ok := nodeMap[*ca.ParentCAID]; ok {
				parent.Children = append(parent.Children, node)
				node.Depth = parent.Depth + 1
			} else {
				// Parent not found in DB, treat as top-level
				rootNodes = append(rootNodes, node)
			}
		} else {
			rootNodes = append(rootNodes, node)
		}
	}

	return rootNodes, nil
}
