package logbuf

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	cmtlog "github.com/cometbft/cometbft/libs/log"
)

func TestBuffer(t *testing.T) {
	b := &Buffer{max: 1 << 20}
	slog.New(slog.NewJSONHandler(b, nil)).Info("from slog", "k", "v")
	cmtlog.NewTMLogger(cmtlog.NewSyncWriter(b)).Info("from comet", "k", "v")
	lines, truncated := b.Lines(0, 1<<20)
	if len(lines) != 2 || truncated || !strings.Contains(lines[0], "from slog") || !strings.Contains(lines[1], "from comet") {
		t.Fatalf("got %q truncated=%v", lines, truncated)
	}
	if lines, _ := b.Lines(time.Now().Add(time.Minute).UnixMilli(), 1<<20); len(lines) != 0 {
		t.Fatalf("since in the future returned %q", lines)
	}
	if lines, truncated := b.Lines(0, len(lines[0])+1); len(lines) != 1 || !truncated {
		t.Fatalf("byte cap: got %d lines truncated=%v", len(lines), truncated)
	}

	b = &Buffer{max: 1 << 20, entries: []entry{{1, "a"}, {2, "b"}, {2, "c"}, {3, "d"}}}
	if lines, _ := b.Lines(2, 1<<20); len(lines) != 3 || !strings.HasSuffix(lines[0], " b") {
		t.Fatalf("since boundary: got %q", lines)
	}

	b = &Buffer{max: 100}
	for i := 0; i < 10; i++ {
		fmt.Fprintf(b, "line %02d padding padding\n", i)
	}
	lines, _ = b.Lines(0, 1<<20)
	if len(lines) != 4 || !strings.HasSuffix(lines[3], "line 09 padding padding") || b.size > 100 {
		t.Fatalf("after eviction: %q size=%d", lines, b.size)
	}
}
