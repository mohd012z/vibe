package com.vibe.hermesinspector;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;

/**
 * Conservative DEX explanation. "Pseudocode" shows what the bytecode explicitly
 * says, NOT reconstructed Java/Kotlin control flow. INVOKE references are static
 * callsites; dynamic dispatch/execution is not inferred.
 */
public final class DexViewModes {
    public static final int MODE_BYTECODE=0;
    public static final int MODE_PSEUDOCODE=1;
    public static final int MODE_CALLS=2;
    public static final int MAX_OUTPUT=ApkSourceExplorer.MAX_TEXT;
    private DexViewModes(){}

    static String signature(Method method) {
        StringBuilder b=new StringBuilder(method.getDefiningClass()).append("->")
           .append(method.getName()).append('(');
        for(CharSequence param:method.getParameterTypes())b.append(param);
        return b.append(')').append(method.getReturnType()).toString();
    }

    public static List<String> callTargets(ClassDef cls) {
        LinkedHashSet<String> targets=new LinkedHashSet<>();
        int methods=0, instructions=0;
        for(Method method:cls.getMethods()){
            if(++methods>ApkSourceExplorer.MAX_CLASS_METHODS)break;
            MethodImplementation implementation=method.getImplementation();
            if(implementation==null)continue;
            for(Instruction ins:implementation.getInstructions()){
                if(++instructions>ApkSourceExplorer.MAX_INSTRUCTIONS)return new ArrayList<>(targets);
                if(!ins.getOpcode().name.startsWith("invoke-"))continue;
                if(!(ins instanceof ReferenceInstruction))continue;
                Object ref=((ReferenceInstruction)ins).getReference();
                if(ref instanceof MethodReference){
                    MethodReference m=(MethodReference)ref;
                    if(targets.size()<300)
                        targets.add(m.getDefiningClass()+"->"+m.getName());
                }
            }
        }
        return new ArrayList<>(targets);
    }

    public static String render(ClassDef cls,int mode) {
        if(mode==MODE_BYTECODE)return ApkSourceExplorer.formatClass(cls);
        if(mode!=MODE_PSEUDOCODE&&mode!=MODE_CALLS)
            throw new IllegalArgumentException("Unsupported source mode");
        StringBuilder out=new StringBuilder();
        out.append(mode==MODE_PSEUDOCODE?
            "// Inferred bytecode commentary; NOT original Java/Kotlin source.\n":
            "# EXPLICIT invoke-* references only; not a dynamic call graph.\n");
        out.append("// class ").append(cls.getType()).append("\n\n");
        int methods=0,opcodes=0;
        for(Method method:cls.getMethods()){
            if(++methods>ApkSourceExplorer.MAX_CLASS_METHODS||out.length()>MAX_OUTPUT) {
                out.append("// Preview limit reached\n");break;
            }
            String caller=signature(method);
            out.append(mode==MODE_CALLS?"METHOD ":"method ").append(caller).append("\n");
            MethodImplementation impl=method.getImplementation();
            if(impl==null){
                if(mode==MODE_PSEUDOCODE)out.append("  // native or abstract; no code body\n");
                continue;
            }
            int address=0,edges=0;
            for(Instruction ins:impl.getInstructions()){
                if(++opcodes>ApkSourceExplorer.MAX_INSTRUCTIONS||out.length()>MAX_OUTPUT){
                    out.append("  // Instruction budget reached\n");
                    return out.toString();
                }
                String opcode=ins.getOpcode().name;
                if(ins instanceof ReferenceInstruction && opcode.startsWith("invoke-")) {
                    Object ref=((ReferenceInstruction)ins).getReference();
                    if(ref instanceof MethodReference){
                        MethodReference m=(MethodReference)ref;
                        String callee=m.getDefiningClass()+"->"+m.getName();
                        if(mode==MODE_CALLS){
                            out.append("  @+").append(address).append("  ").append(opcode)
                               .append(" ").append(callee).append("\n");
                            edges++;
                        }else {
                            out.append("  // bytecode callsite @+").append(address).append(": ")
                               .append(opcode).append(" ").append(callee).append("\n");
                        }
                    }
                }else if(mode==MODE_PSEUDOCODE){
                    if(opcode.startsWith("return"))out.append("  // ").append(opcode).append("\n");
                    else if(opcode.startsWith("const"))out.append("  // ").append(opcode)
                       .append(" (constant assignment)\n");
                    else if(opcode.startsWith("if-")||opcode.startsWith("goto"))
                        out.append("  // branch @+").append(address).append(": ").append(opcode).append("\n");
                    else if(opcode.startsWith("new-"))
                        out.append("  // allocation: ").append(opcode).append("\n");
                }
                address+=ins.getCodeUnits();
            }
            if(mode==MODE_CALLS && edges==0)out.append("  (no explicit invoke instructions)\n");
            out.append("\n");
        }
        return out.toString();
    }
}
