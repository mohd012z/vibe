package org.r2aistudio.offline;
/** Monotonic operation generations prevent obsolete background results from updating the UI. */
public final class OperationGate {
    private long generation;
    private boolean closed;
    public synchronized long begin() {
        if (closed) throw new IllegalStateException("gate closed");
        return ++generation;
    }
    public synchronized void cancel() { ++generation; }
    public synchronized boolean isCurrent(long token) { return !closed && token == generation; }
    public synchronized void close() { closed = true; ++generation; }
}
