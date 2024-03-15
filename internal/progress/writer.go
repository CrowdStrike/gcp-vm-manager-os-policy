// Package progress provides a io.Writer that can be used to track progress of writes.
package progress

import (
	"sync"
)

type ProgressWriter struct {
	lock sync.RWMutex

	n     int64
	total int64
}

// NewWriter creates a writer that counts the number of bytes written.
func NewProgressWriter() *ProgressWriter {
	return &ProgressWriter{}
}

// Write updates the total bytes written.
func (pw *ProgressWriter) Write(p []byte) (int, error) {
	pw.lock.Lock()
	defer pw.lock.Unlock()
	pw.n += int64(len(p))
	return len(p), nil
}

// N gets the total number of bytes written.
func (pw *ProgressWriter) N() int64 {
	var n int64
	pw.lock.RLock()
	n = pw.n
	pw.lock.RUnlock()
	return n
}

// Total the total bytes to be written.
func (pw *ProgressWriter) Total() int64 {
	var total int64
	pw.lock.RLock()
	defer pw.lock.RUnlock()
	total = pw.total
	return total
}

// SetTotal sets the total bytes to be written.
func (pw *ProgressWriter) SetTotal(total int64) {
	pw.lock.Lock()
	defer pw.lock.Unlock()
	pw.total = total
}

// Done returns true if the number of bytes written is equal to the total bytes.
func (pw *ProgressWriter) Done() bool {
	pw.lock.RLock()
	defer pw.lock.RUnlock()
	if pw.total == pw.n {
		return true
	}
	return false
}
