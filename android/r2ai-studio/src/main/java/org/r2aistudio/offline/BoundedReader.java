package org.r2aistudio.offline;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/** Bounded, cancellable, no-network stream reader. Does not close caller-owned stream. */
public final class BoundedReader {
    public interface Cancellation { boolean isCancelled(); }
    private BoundedReader() {}
    public static byte[] read(InputStream input, int maxBytes, Cancellation cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(cancellation, "cancellation");
        if(maxBytes < 1 || maxBytes > OfflineInspector.MAX_INPUT_BYTES)
            throw new IllegalArgumentException("invalid maximum");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while(true) {
            if(cancellation.isCancelled() || Thread.currentThread().isInterrupted())
                throw new CancellationException("inspection cancelled");
            int remaining = maxBytes - out.size();
            int n = input.read(buffer, 0, Math.min(buffer.length, remaining+1));
            if(n == -1) break;
            if(n == 0) {
                int single = input.read();
                if(single == -1) break;
                if(remaining == 0) throw new IOException("file exceeds limit");
                out.write(single);
            } else {
                if(n > remaining) throw new IOException("file exceeds limit");
                out.write(buffer, 0, n);
            }
        }
        if(cancellation.isCancelled() || Thread.currentThread().isInterrupted())
            throw new CancellationException("inspection cancelled");
        return out.toByteArray();
    }
}
