package deploy

import (
	"context"
	"fmt"
)

// TypeAgent is a host running the CertPilot agent.
const TypeAgent = "agent"

// agentDeployer exists so that an agent target is a target like any other
// everywhere the rest of this package looks — and refuses, loudly, at the one
// place it is different.
//
// The difference is direction. Every other deployer here opens a connection to
// the place the certificate is going. An agent host is behind two firewalls
// with nothing able to reach inwards, which is the entire reason it runs an
// agent, so the host claims the job over its own signed API and installs it
// from a spec that lives on the host. The queue, the lease, the retry curve and
// the attempt log are identical; only the worker moves.
//
// This type is the backstop for that. The core's claim query already skips
// agent targets, and if it ever stops doing so, the failure should be one
// sentence naming the reason rather than a nil dereference or — far worse — a
// silent success on a host nothing ever wrote to.
type agentDeployer struct{}

func (agentDeployer) Type() string { return TypeAgent }

func (agentDeployer) Describe() string { return "a host running the CertPilot agent" }

// NeedsPrivateKey is false, and it is a fact rather than a default.
//
// The key was generated on that host and is already sitting beside where it is
// going. `deploys_private_key` exists so a security team can answer "where does
// this organisation ship private keys" with a SELECT and no KEK; agent hosts
// being absent from that answer is the property step 4c was for.
func (agentDeployer) NeedsPrivateKey() bool { return false }

func (agentDeployer) Deploy(ctx context.Context, b Bundle) (string, error) {
	return "", fmt.Errorf(
		"this target is a host running the CertPilot agent, and the host installs its own certificates — nothing here can reach inwards to it. The job is claimed by the agent on its next cycle")
}

// newAgentDeployer refuses to be configured by hand.
//
// An agent target is created by an agent reporting a destination, not by
// somebody filling in a form. A hand-made one would carry an agent_id nobody
// checked, or none at all, and would sit in the target list looking operable
// while no host on earth would ever claim a job for it.
func newAgentDeployer(config map[string]any) (Deployer, error) {
	if len(config) > 0 {
		return nil, fmt.Errorf(
			"an agent target takes no configuration; it is created when a host running the agent reports where it installs certificates")
	}
	return agentDeployer{}, nil
}
