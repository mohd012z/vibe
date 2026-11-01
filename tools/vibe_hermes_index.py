"""Bounded, deterministic reference index for HBC-Tool instruction.hasm.

Only explicit 'String(ID)' disassembler annotations are counted as string
references. Indirect calls and inferred function call graphs are NOT claimed.
No execution or untrusted regular-expression interpolation.
"""
from __future__ import annotations
import re

HEADER=re.compile(r"^Function<([^\n>]*)>([0-9]{1,10})\(")
STRING=re.compile(r";\s*Oper\[[0-9]{1,5}\]:\s*String\(([0-9]{1,10})\)")
MAX_FUNCTIONS=2000
MAX_REFERENCES=10000
MAX_LINE=8192

def function_index(hasm: str, max_functions: int = MAX_FUNCTIONS,
                   max_references: int = MAX_REFERENCES) -> dict:
    if not isinstance(hasm,str):
        raise TypeError("HASM source must be text")
    if not 1<=max_functions<=MAX_FUNCTIONS or not 0<=max_references<=MAX_REFERENCES:
        raise ValueError("Invalid index budgets")
    functions=[]
    references=0
    current=None
    current_refs=set()
    pending_instruction=False
    used_ids=set()
    truncated=False
    for line in hasm.splitlines():
        if len(line)>MAX_LINE:
            truncated=True
            continue
        m=HEADER.match(line)
        if m:
            if len(functions)>=max_functions:
                truncated=True
                current=None
                continue
            fid=int(m.group(2))
            if fid > 0xffffffff:
                truncated=True
                current=None
                continue
            if fid in used_ids:
                raise ValueError("Duplicate HASM function ID")
            used_ids.add(fid)
            current_refs=set()
            pending_instruction=False
            current={"id":fid,"name":m.group(1)[:200],"string_refs":[],
                     "instruction_count":0}
            functions.append(current)
            continue
        if line.strip()=="EndFunction":
            current=None
            pending_instruction=False
            continue
        if current is None:
            continue
        if not line.strip() or line.lstrip().startswith(";"):
            if line.lstrip().startswith(";") and pending_instruction:
                for match in STRING.finditer(line):
                    if references>=max_references:
                        truncated=True
                        break
                    sid=int(match.group(1))
                    if sid > 0xffffffff:
                        truncated=True
                        continue
                    references+=1
                    if sid not in current_refs:
                        current_refs.add(sid)
                        current["string_refs"].append(sid)
            if not line.strip():
                pending_instruction=False
            continue
        # Only count actual assembler instruction lines; never accept prose.
        if line.startswith("\t") and re.match(r"^\t[A-Za-z][A-Za-z0-9_]*\s+",line):
            current["instruction_count"]+=1
            pending_instruction=True
        else:
            pending_instruction=False
    return {"functions":functions, "function_count":len(functions),
            "references_scanned":references,"truncated":truncated,
            "call_graph_proven":False,
            "reference_provenance":"explicit String(ID) comments following instructions"}
