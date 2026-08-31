package tests

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jsiebens/ionscale/tests/sc"
	"github.com/jsiebens/ionscale/tests/tsn"
	"github.com/stretchr/testify/require"
)

var (
	tlpubRegex             = regexp.MustCompile(`tlpub:[0-9a-f]+`)
	disablementSecretRegex = regexp.MustCompile(`disablement-secret:[0-9A-Fa-f]+`)
	nodekeyRegex           = regexp.MustCompile(`nodekey:[0-9a-f]+`)
)

func TestTailnetLock(t *testing.T) {
	sc.Run(t, func(s *sc.Scenario) {
		tailnet := s.CreateTailnet()
		s.EnableTailnetLock(tailnet.Id)
		authKey := s.CreateAuthKey(tailnet.Id, false)

		initiator := s.NewTailscaleNode()
		require.NoError(t, initiator.Up(authKey))

		// discover the node's own tailnet-lock public key
		statusOut, _, err := initiator.Tailscale("lock", "status")
		require.NoError(t, err)
		tlpub := tlpubRegex.FindString(statusOut)
		require.NotEmpty(t, tlpub, "no tailnet lock key in: %s", statusOut)

		// initialize the key authority, trusting this node's lock key
		initOut, initErr, err := initiator.Tailscale("lock", "init", "--confirm", "--gen-disablements=1", tlpub)
		require.NoError(t, err, "lock init failed: %s %s", initOut, initErr)
		secret := disablementSecretRegex.FindString(initOut + initErr)
		require.NotEmpty(t, secret, "no disablement secret in: %s %s", initOut, initErr)

		require.NoError(t, initiator.WaitFor(tsn.IsRunning()))

		statusOut, _, err = initiator.Tailscale("lock", "status")
		require.NoError(t, err)
		require.Contains(t, statusOut, "Tailnet lock is ENABLED", "unexpected lock status: %s", statusOut)

		// a second node joins after enablement; it is unsigned and must not
		// see (or be seen by) the initiator until it is signed
		joiner := s.NewTailscaleNode()
		require.NoError(t, joiner.Up(authKey))

		statusOut, _, err = joiner.Tailscale("lock", "status")
		require.NoError(t, err)
		joinerKey := nodekeyRegex.FindString(statusOut)
		if joinerKey == "" {
			// fall back to the plain status output for the node key
			nodeStatus, _, err := joiner.Tailscale("status", "--self", "--peers=false")
			require.NoError(t, err)
			joinerKey = nodekeyRegex.FindString(nodeStatus)
		}
		require.NotEmpty(t, joinerKey, "unable to determine joiner node key")

		// sign the joiner from the node holding the trusted lock key
		signOut, signErr, err := initiator.Tailscale("lock", "sign", joinerKey)
		require.NoError(t, err, "lock sign failed: %s %s", signOut, signErr)

		require.NoError(t, initiator.WaitFor(tsn.PeerCount(1)))
		require.NoError(t, joiner.WaitFor(tsn.PeerCount(1)))

		// disable the lock with the disablement secret
		disableOut, disableErr, err := initiator.Tailscale("lock", "disable", secret)
		require.NoError(t, err, "lock disable failed: %s %s", disableOut, disableErr)

		require.NoError(t, waitForLockDisabled(initiator))
		require.NoError(t, initiator.WaitFor(tsn.PeerCount(1)))
		require.NoError(t, joiner.WaitFor(tsn.PeerCount(1)))
	})
}

func waitForLockDisabled(node *tsn.TailscaleNode) error {
	var lastOut string
	for i := 0; i < 30; i++ {
		out, _, err := node.Tailscale("lock", "status")
		if err == nil && !strings.Contains(out, "ENABLED") {
			return nil
		}
		lastOut = out
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("tailnet lock still enabled: %s", lastOut)
}
