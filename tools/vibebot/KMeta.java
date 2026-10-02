import java.nio.file.*;
import org.jetbrains.kotlin.metadata.ProtoBuf;
import org.jetbrains.kotlin.metadata.jvm.deserialization.*;

public class KMeta {
    public static void main(String[] args) throws Exception {
        byte[] d1raw = Files.readAllBytes(Paths.get(args[0]));
        String d1 = new String(d1raw, "ISO-8859-1");
        String[] d2 = Files.readAllLines(Paths.get(args[1]))
                .toArray(new String[0]);
        System.out.println("d1 chars=" + d1.length()
                + " first=U+" + String.format("%04x", (int) d1.charAt(0)));
        System.out.println("d2 entries=" + d2.length);

        byte[] proto = BitEncoding.decodeBytes(new String[]{d1});
        System.out.println("BitEncoding.decodeBytes -> " + proto.length
                + " proto bytes");

        kotlin.Pair<JvmNameResolver, ProtoBuf.Class> res =
            JvmProtoBufUtil.readClassDataFrom(proto, d2);
        JvmNameResolver r = res.getFirst();
        ProtoBuf.Class c = res.getSecond();

        System.out.println("CLASS fq_name idx=" + c.getFqName()
                + " -> " + r.getQualifiedClassName(c.getFqName()));
        for (int n : c.getNestedClassNameList())
            System.out.println("  nested idx=" + n + " -> "
                    + r.getQualifiedClassName(n));
        for (ProtoBuf.Constructor ct : c.getConstructorList())
            System.out.println("  ctor (name=<init>)");
        for (ProtoBuf.Function f : c.getFunctionList())
            System.out.println("  fn   idx=" + f.getName()
                    + " name=" + r.getString(f.getName()));
        for (ProtoBuf.Property p : c.getPropertyList())
            System.out.println("  prop idx=" + p.getName()
                    + " name=" + r.getString(p.getName()));
        System.out.println("OK");
    }
}
