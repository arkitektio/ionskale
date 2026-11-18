package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/jsiebens/ionscale/pkg/client/ionscale"
	"github.com/jsiebens/ionscale/pkg/defaults"
	"github.com/jsiebens/ionscale/tests/sc"
	"github.com/jsiebens/ionscale/tests/tsn"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// Two tailscale clients that take no direct path reach each other through a
// third that relays UDP for them (tailscale's peer relays).
//
// It takes two things of the control server: the relay capabilities of the
// policy's grants in the packet filter, and each peer's capability version
// in the netmap (tailcfg.Node.Cap). A client uses a relay only with a peer
// it knows to speak it, so without the version this stays on DERP.
func TestPeerRelay(t *testing.T) {
	sc.Run(t, func(s *sc.Scenario) {
		tailnet := s.CreateTailnet()
		key := s.CreateAuthKey(tailnet.Id, true)

		policy := defaults.DefaultACLPolicy()
		// App grants are passed on as written: both directions are spelled
		// out. Here everyone may ask everyone, and only the one node relays.
		relayCaps := tailcfg.PeerCapMap{
			"tailscale.com/cap/relay":        {},
			"tailscale.com/cap/relay-target": {},
		}
		policy.Grants = []ionscale.ACLGrant{
			{Source: []string{"*"}, Destination: []string{"*"}, App: relayCaps},
		}
		s.SetACLPolicy(tailnet.Id, policy)

		// No direct UDP for the two clients, as behind NATs that let none in.
		neverDirect := sc.WithEnv("TS_DEBUG_NEVER_DIRECT_UDP=true")
		nodeA := s.NewTailscaleNode(neverDirect)
		nodeB := s.NewTailscaleNode(neverDirect)
		relay := s.NewTailscaleNode()

		require.NoError(t, nodeA.Up(key))
		require.NoError(t, nodeB.Up(key))
		require.NoError(t, relay.Up(key))
		_, stderr, err := relay.Tailscale("set", "--relay-server-port=40000")
		require.NoError(t, err, stderr)

		require.NoError(t, nodeA.WaitFor(tsn.PeerCount(2)))
		require.NoError(t, nodeB.WaitFor(tsn.PeerCount(2)))

		deadline := time.Now().Add(90 * time.Second)
		var last string
		for time.Now().Before(deadline) {
			out, _, _ := nodeA.Tailscale("ping", "--timeout=2s", "--c=3", nodeB.IPv4())
			last = out
			if strings.Contains(out, "peer-relay") {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("the ping never went through the peer relay:\n%s", last)
	})
}
