package org.r2aistudio.offline;
public final class OperationGateTest {
    static void ok(boolean b) { if (!b) throw new AssertionError(); }
    public static void main(String[] args) {
        OperationGate g=new OperationGate();
        long a=g.begin();ok(g.isCurrent(a));
        long b=g.begin();ok(!g.isCurrent(a)&&g.isCurrent(b));
        g.cancel();ok(!g.isCurrent(b));
        long c=g.begin();ok(g.isCurrent(c));
        g.close();ok(!g.isCurrent(c));
        try {g.begin();throw new AssertionError();}catch(IllegalStateException expected){}
        System.out.println("PASS: operation generation, cancellation, close, stale results");
    }
}
