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
	// the locked-out client prints the exact command to run on a trusted node:
	// "tailscale lock sign nodekey:<hex> tlpub:<hex>"
	signArgsRegex = regexp.MustCompile(`(nodekey:[0-9a-f]+) (tlpub:[0-9a-f]+)`)
)

// TestTailnetLock exercises the full tailnet-lock lifecycle end to end:
// initializing the key authority, a later node being locked out until signed,
// connectivity under lock, and disablement propagating to every node.
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

		require.NoError(t, waitForLockStatus(initiator, "Tailnet lock is ENABLED"))
		require.NoError(t, initiator.WaitFor(tsn.IsRunning()))

		// a second node joins after enablement: it registers, but is locked
		// out and invisible to the initiator until a trusted key signs it
		joiner := s.NewTailscaleNode()
		joinerUpOut, joinerUpErr, err := joiner.Tailscale("up", "--login-server", "https://ionscale", "--authkey", authKey)
		require.NoError(t, err, "joiner up failed: %s %s", joinerUpOut, joinerUpErr)

		require.NoError(t, waitForLockStatus(joiner, "LOCKED OUT"))

		lockedStatus, _, err := joiner.Tailscale("lock", "status")
		require.NoError(t, err)
		signArgs := signArgsRegex.FindStringSubmatch(lockedStatus)
		require.Len(t, signArgs, 3, "no sign command in locked-out status: %s", lockedStatus)

		// the unsigned node must not appear in the initiator's netmap
		require.NoError(t, initiator.Check(tsn.PeerCount(0)))

		// sign the joiner from the node holding the trusted lock key, using
		// the exact command the locked-out client printed
		signOut, signErrOut, err := initiator.Tailscale("lock", "sign", signArgs[1], signArgs[2])
		require.NoError(t, err, "lock sign failed: %s %s", signOut, signErrOut)

		// both nodes now see each other and traffic flows under lock
		require.NoError(t, waitForLockStatus(joiner, "This node is accessible under tailnet lock"))
		require.NoError(t, joiner.WaitFor(tsn.IsRunning()))
		require.NoError(t, initiator.WaitFor(tsn.PeerCount(1)))
		require.NoError(t, joiner.WaitFor(tsn.PeerCount(1)))
		require.NoError(t, initiator.Ping(joiner.IPv4()))

		// disable the lock with the disablement secret; every node verifies
		// the secret via bootstrap and disables its local authority
		disableOut, disableErrOut, err := initiator.Tailscale("lock", "disable", secret)
		require.NoError(t, err, "lock disable failed: %s %s", disableOut, disableErrOut)

		require.NoError(t, waitForLockStatus(initiator, "Tailnet lock is NOT enabled"))
		require.NoError(t, waitForLockStatus(joiner, "Tailnet lock is NOT enabled"))
		require.NoError(t, initiator.WaitFor(tsn.PeerCount(1)))
		require.NoError(t, joiner.WaitFor(tsn.PeerCount(1)))
		require.NoError(t, initiator.Ping(joiner.IPv4()))
	})
}

// waitForLockStatus polls `tailscale lock status` until its output contains
// marker. Matching is case-insensitive: the CLI wording changed casing across
// versions (e.g. "Tailnet lock is ENABLED" vs "Tailnet Lock is ENABLED").
func waitForLockStatus(node *tsn.TailscaleNode, marker string) error {
	var lastOut string
	var lastErr error
	lowerMarker := strings.ToLower(marker)
	for i := 0; i < 45; i++ {
		out, _, err := node.Tailscale("lock", "status")
		if err == nil && strings.Contains(strings.ToLower(out), lowerMarker) {
			return nil
		}
		lastOut, lastErr = out, err
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("lock status never contained %q; last output: %s (err: %v)", marker, lastOut, lastErr)
}
