package tests

import (
	"github.com/jsiebens/ionscale/tests/sc"
	"github.com/jsiebens/ionscale/tests/tsn"
	"github.com/stretchr/testify/require"
	"testing"
)

// An expired machine is quarantined server-side: peers stop seeing it and it
// stops seeing its peers, instead of merely being flagged as expired.
func TestExpiredPeersAreRemoved(t *testing.T) {
	sc.Run(t, func(s *sc.Scenario) {
		tailnet := s.CreateTailnet()
		key := s.CreateAuthKey(tailnet.Id, true)

		nodeA := s.NewTailscaleNode()
		nodeB := s.NewTailscaleNode()

		require.NoError(t, nodeA.Up(key))
		require.NoError(t, nodeB.Up(key))
		require.NoError(t, nodeB.WaitFor(tsn.HasPeer(nodeA.Hostname())))

		machineA, err := s.FindMachine(tailnet.Id, nodeA.Hostname())
		require.NoError(t, err)
		s.ExpireMachine(machineA)

		// B drops A ...
		require.NoError(t, nodeB.WaitFor(tsn.PeerCount(0)))
		// ... and A no longer learns about anyone
		require.NoError(t, nodeA.WaitFor(tsn.PeerCount(0)))

		// a node joining later never sees the expired machine at all
		nodeC := s.NewTailscaleNode()
		require.NoError(t, nodeC.Up(key))
		require.NoError(t, nodeC.WaitFor(tsn.HasPeer(nodeB.Hostname()), tsn.PeerCount(1)))
	})
}
