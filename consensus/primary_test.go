package consensus

import (
	"testing"
	"time"
)

func TestPrimaryArbiter(t *testing.T) {
	a := NewPrimaryArbiter(time.Minute, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("nodeA") {
		t.Fatal("first node should become primary")
	}
	if a.Primary() != "nodeA" {
		t.Fatalf("primary = %q, want nodeA", a.Primary())
	}
	if !a.Acquire("nodeA") {
		t.Fatal("primary should always re-acquire")
	}
	if a.Acquire("nodeB") {
		t.Fatal("non-primary refused while primary is fresh")
	}

	// Within the timeout, still refused.
	a.now = func() time.Time { return base.Add(30 * time.Second) }
	if a.Acquire("nodeB") {
		t.Fatal("non-primary refused within timeout")
	}
	// Primary keeps signing -> refreshes the idle timer.
	if !a.Acquire("nodeA") {
		t.Fatal("primary re-acquire")
	}

	// Primary idle past the timeout -> nodeB takes over.
	a.now = func() time.Time { return base.Add(30*time.Second + time.Minute + time.Second) }
	if !a.Acquire("nodeB") {
		t.Fatal("non-primary should take over after primary idle past timeout")
	}
	if a.Primary() != "nodeB" {
		t.Fatalf("primary = %q, want nodeB after failover", a.Primary())
	}
	if a.Acquire("nodeA") {
		t.Fatal("old primary refused while new primary is fresh")
	}
}

// TestPrimaryArbiterPrefersFirstTarget covers the deployment shape this exists
// for: a co-located node listed first and a remote standby second. The standby
// only signs while the preferred node is away, and hands the role straight back
// when it returns.
func TestPrimaryArbiterPrefersFirstTarget(t *testing.T) {
	const (
		preferred = "10.0.0.1:26659" // co-located node, listed first
		standby   = "10.0.0.2:26659" // remote standby
	)
	a := NewPreferringPrimaryArbiter(time.Minute, []string{preferred, standby}, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire(preferred) {
		t.Fatal("preferred node should become primary")
	}
	if a.Acquire(standby) {
		t.Fatal("standby must not preempt the preferred node")
	}

	// Preferred node's link drops; after the idle timeout the standby takes over.
	a.now = func() time.Time { return base.Add(time.Minute + time.Second) }
	if !a.Acquire(standby) {
		t.Fatal("standby should take over once the preferred node is idle")
	}
	if a.Primary() != standby {
		t.Fatalf("primary = %q, want %q", a.Primary(), standby)
	}

	// Preferred node returns and reclaims immediately, without waiting for the
	// standby to go idle.
	a.now = func() time.Time { return base.Add(time.Minute + 2*time.Second) }
	if !a.Acquire(preferred) {
		t.Fatal("preferred node should fail back as soon as it requests again")
	}
	if a.Primary() != preferred {
		t.Fatalf("primary = %q, want %q after failback", a.Primary(), preferred)
	}
	if a.Acquire(standby) {
		t.Fatal("standby must be refused again once the preferred node is back")
	}
}

// TestPrimaryArbiterUnlistedRanksLast ensures a target missing from the
// preference list never preempts a listed one, and cannot be preempted by
// rank alone once it holds the role legitimately.
func TestPrimaryArbiterUnlistedRanksLast(t *testing.T) {
	a := NewPreferringPrimaryArbiter(time.Minute, []string{"listed"}, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("unlisted") {
		t.Fatal("first requester becomes primary regardless of ranking")
	}
	if !a.Acquire("listed") {
		t.Fatal("listed node outranks an unlisted primary")
	}
	if a.Acquire("unlisted") {
		t.Fatal("unlisted node must not preempt a listed primary")
	}
}

// TestPrimaryArbiterWithoutPreferenceKeepsRole documents that the default
// constructor is unchanged: without a preference order the node that took over
// keeps signing until it goes idle.
func TestPrimaryArbiterWithoutPreferenceKeepsRole(t *testing.T) {
	a := NewPrimaryArbiter(time.Minute, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("nodeA") {
		t.Fatal("first node should become primary")
	}
	a.now = func() time.Time { return base.Add(time.Minute + time.Second) }
	if !a.Acquire("nodeB") {
		t.Fatal("nodeB takes over after idle timeout")
	}
	// nodeA is not preferred over nodeB, so it must wait for another idle window.
	if a.Acquire("nodeA") {
		t.Fatal("without a preference order there is no fail-back")
	}
}
