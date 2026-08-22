// Command certpilot-agent runs on the machines where certificates actually
// live.
//
// The agent generates its keys on the host and never sends a private one
// anywhere — starting with its own identity key, which it creates during
// enrolment. That is the whole architectural claim, and it is why this is a
// separate binary and a separate Go module: it must be small, it must be
// installable on a machine that can reach nothing but the core, and it must not
// link a line of the core's database code.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/certpilot/certpilot/agent"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "enrol", "enroll":
		err = runEnrol(ctx, os.Args[2:])
	case "run":
		err = runAgent(ctx, os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `certpilot-agent — the CertPilot host agent

  certpilot-agent enrol  --server=URL --token=TOKEN [--name=NAME] [--interval=5m]
  certpilot-agent run    [--state-dir=DIR]
  certpilot-agent status [--state-dir=DIR]

Enrolment generates this host's identity key locally. The private half is never
sent to the core and there is no flag that would send it.

State directory defaults to `+"`"+`$CERTPILOT_AGENT_STATE`+"`"+`, then /var/lib/certpilot-agent
when running as root, then ~/.certpilot-agent.
`)
}

func runEnrol(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enrol", flag.ExitOnError)
	server := fs.String("server", "", "CertPilot core base URL, e.g. https://certpilot.internal:8080")
	token := fs.String("token", "", "an enrolment token")
	name := fs.String("name", "", "what to call this host in CertPilot (defaults to its hostname)")
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where to keep this agent's identity")
	interval := fs.Duration("interval", 5*time.Minute, "how often this agent will report")
	if err := fs.Parse(args); err != nil {
		return err
	}

	result, err := agent.Enrol(ctx, agent.EnrolOptions{
		Server:   *server,
		Token:    *token,
		Name:     *name,
		StateDir: *stateDir,
		Interval: *interval,
	})
	if err != nil {
		return err
	}

	// The key id is printed so an operator can compare it with the row in
	// CertPilot and answer "is the agent enrolled under this name the machine I
	// ran this on" without trusting the name, which anybody can set.
	fmt.Printf("Enrolled as %q\n", result.Name)
	fmt.Printf("  agent id : %s\n", result.AgentID)
	fmt.Printf("  key id   : %s\n", result.KeyID)
	fmt.Printf("  identity : %s (private key never leaves this host)\n", *stateDir)
	fmt.Printf("\nStart reporting with: certpilot-agent run --state-dir=%s\n", *stateDir)
	return nil
}

func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where this agent's identity is kept")
	once := fs.Bool("once", false, "report a single heartbeat and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key, state, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}

	runner := agent.NewRunner(agent.NewClient(state.Server, state.AgentID, key), state)
	if *once {
		if _, err := runner.Heartbeat(ctx); err != nil {
			return err
		}
		fmt.Println("reported")
		return nil
	}
	return runner.Run(ctx)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where this agent's identity is kept")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, state, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}
