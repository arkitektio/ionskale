package core

import (
	"context"
	"github.com/jsiebens/ionscale/internal/domain"
	"go.uber.org/zap"
	"time"
)

const (
	ticker            = 10 * time.Minute
	inactivityTimeout = 30 * time.Minute
	// expirySweepInterval bounds how long an expired machine stays visible to
	// its peers: nothing else triggers a netmap push when a key lapses on its
	// own.
	expirySweepInterval = 1 * time.Minute
)

func StartWorker(repository domain.Repository, sessionManager PollMapSessionManager) {
	r := &worker{
		sessionManager: sessionManager,
		repository:     repository,
	}

	go r.start()
	go r.startExpirySweeper()
}

type worker struct {
	sessionManager PollMapSessionManager
	repository     domain.Repository
}

func (r *worker) start() {
	r.deleteInactiveEphemeralNodes()
	t := time.NewTicker(ticker)
	for range t.C {
		r.deleteInactiveEphemeralNodes()
	}
}

func (r *worker) startExpirySweeper() {
	prev := time.Now().UTC()
	t := time.NewTicker(expirySweepInterval)
	for now := range t.C {
		now = now.UTC()
		r.notifyExpiredMachines(prev, now)
		prev = now
	}
}

// notifyExpiredMachines pushes a netmap update to every tailnet in which a
// machine's key expired since the previous sweep, so peers drop the machine
// (see Machine.IsQuarantined) without waiting for an unrelated change.
func (r *worker) notifyExpiredMachines(from, to time.Time) {
	machines, err := r.repository.ListMachinesExpiredBetween(context.Background(), from, to)
	if err != nil {
		zap.L().Warn("unable to list expired machines", zap.Error(err))
		return
	}

	tailnets := make(map[uint64]bool)
	for _, m := range machines {
		tailnets[m.TailnetID] = true
	}

	for id := range tailnets {
		r.sessionManager.NotifyAll(id)
	}
}

func (r *worker) deleteInactiveEphemeralNodes() {
	ctx := context.Background()

	now := time.Now().UTC()
	checkpoint := now.Add(-inactivityTimeout)
	machines, err := r.repository.ListInactiveEphemeralMachines(ctx, checkpoint)
	if err != nil {
		return
	}

	var removedNodes = make(map[uint64][]uint64)
	for _, m := range machines {
		if now.After(m.LastSeen.Add(inactivityTimeout)) {
			ok, err := r.repository.DeleteMachine(ctx, m.ID)
			if err != nil {
				continue
			}
			if ok {
				removedNodes[m.TailnetID] = append(removedNodes[m.TailnetID], m.ID)
			}
		}
	}

	if len(removedNodes) != 0 {
		for i, _ := range removedNodes {
			r.sessionManager.NotifyAll(i)
		}
	}
}
