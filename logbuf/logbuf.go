// Package logbuf keeps recent log lines in memory for GET /logs.
package logbuf

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const TimeLayout = "2006-01-02T15:04:05.000Z"

var Default = &Buffer{max: 64 << 20}

type entry struct {
	t    int64 // UnixMilli
	line string
}

// Buffer stores each Write as one line and drops the oldest past max bytes.
type Buffer struct {
	mu      sync.Mutex
	max     int
	size    int
	entries []entry
	head    int
}

// Write never fails, so it does not stop the io.MultiWriter it sits in.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entry{time.Now().UnixMilli(), string(p)})
	b.size += len(p)
	for b.size > b.max {
		b.size -= len(b.entries[b.head].line)
		b.entries[b.head] = entry{}
		b.head++
	}
	if b.head > len(b.entries)/2 {
		n := copy(b.entries, b.entries[b.head:])
		clear(b.entries[n:])
		b.entries, b.head = b.entries[:n], 0
	}
	return len(p), nil
}

// Lines returns lines written at or after since, up to maxBytes in total.
func (b *Buffer) Lines(since int64, maxBytes int) (lines []string, truncated bool) {
	b.mu.Lock()
	live := b.entries[b.head:]
	start := sort.Search(len(live), func(i int) bool { return live[i].t >= since })
	end, size := start, 0
	for ; end < len(live); end++ {
		size += len(TimeLayout) + 1 + len(strings.TrimSuffix(live[end].line, "\n")) + 1 // newline
		if size > maxBytes {
			truncated = true
			break
		}
	}
	picked := append([]entry(nil), live[start:end]...)
	b.mu.Unlock()

	lines = make([]string, len(picked))
	for i, e := range picked {
		lines[i] = time.UnixMilli(e.t).UTC().Format(TimeLayout) + " " + strings.TrimSuffix(e.line, "\n")
	}
	return lines, truncated
}
