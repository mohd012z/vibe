"""Bounded instruction opcode-sequence comparison of HBC-Tool vs hermes-dec.

Only compares opcode names and their per-function order. It does NOT infer
operand equivalence, call-graph semantics, or runtime equivalence.
"""
from __future__ import annotations
import re
from pathlib import Path

HBC_HEADER=re.compile(r"^Function<.*?>([0-9]{1,10})\(")
OFFICIAL_HEADER=re.compile(r"^(?:NC)?Function<.*?>([0-9]{1,10})\(")
HBC_OPCODE=re.compile(r"^\t([A-Za-z][A-Za-z0-9_]*) *\t")
P1_HEADER=re.compile(r'^=> \[(?:Function|Generator function|Async function) #([0-9]{1,10}) ')
P1_OPCODE=re.compile(r"^==> [0-9A-Fa-f]{8}: <([A-Za-z][A-Za-z0-9_]*)>:")
OFFICIAL_OPCODE=re.compile(r"^\[@\s*[0-9]+\]\s+([A-Za-z][A-Za-z0-9_]*)\b")
MAX_BYTES=64*1024*1024
MAX_OPCODES=1000000
MAX_FUNCTIONS=20000

def parse(path:Path,provider:str)->dict[int,tuple[str,...]]:
    if provider not in ("hbctool","hermes_dec","official_hbcdump"):
        raise ValueError("Unknown provider")
    if not path.is_file() or path.is_symlink() or path.stat().st_size>MAX_BYTES:
        raise ValueError("Missing or oversized opcode listing")
    functions={}
    current=None
    count=0
    with path.open("r",encoding="utf-8",errors="replace") as f:
        for line in f:
            header=(HBC_HEADER if provider=="hbctool" else OFFICIAL_HEADER if provider=="official_hbcdump" else P1_HEADER).match(line)
            if header:
                fid=int(header.group(1))
                if fid>0xffffffff or fid in functions or len(functions)>=MAX_FUNCTIONS:
                    raise ValueError("Malformed or repeated function index")
                functions[fid]=[]
                current=fid
                continue
            if provider=="hbctool" and line.startswith("EndFunction"):
                current=None
                continue
            if current is None:
                continue
            matcher=HBC_OPCODE if provider=="hbctool" else OFFICIAL_OPCODE if provider=="official_hbcdump" else P1_OPCODE
            inst=matcher.match(line)
            if inst:
                functions[current].append(inst.group(1))
                count+=1
                if count>MAX_OPCODES:
                    raise ValueError("Opcode count budget exhausted")
    return {fid:tuple(opcodes) for fid,opcodes in functions.items()}

def parity(hbc:Path,p1:Path)->dict:
    a=parse(hbc,"hbctool")
    b=parse(p1,"hermes_dec")
    mismatches=[]
    all_ids=set(a)|set(b)
    for fid in sorted(all_ids):
        if a.get(fid)!=b.get(fid):
            left=a.get(fid,())
            right=b.get(fid,())
            idx=next((i for i in range(min(len(left),len(right))) if left[i]!=right[i]),
                     min(len(left),len(right)))
            if len(mismatches)<10:
                mismatches.append({"function_id":fid,"first_difference":idx,
                     "hbctool":left[idx] if idx<len(left) else None,
                     "hermes_dec":right[idx] if idx<len(right) else None,
                     "hbctool_count":len(left),"hermes_dec_count":len(right)})
    return {"hbctool_functions":len(a),"hermes_dec_functions":len(b),
            "hbctool_opcodes":sum(map(len,a.values())),
            "hermes_dec_opcodes":sum(map(len,b.values())),
            "functions_disagreeing":sum(a.get(i)!=b.get(i) for i in all_ids),
            "first_mismatches":mismatches,
            "opcode_name_sequence_equal":all(a.get(i)==b.get(i) for i in all_ids),
            "operands_and_semantics":"not_compared"}

if __name__=="__main__":
    import argparse,json
    parser=argparse.ArgumentParser()
    parser.add_argument("hbctool_hasm",type=Path)
    parser.add_argument("hermes_dec_hasm",type=Path)
    args=parser.parse_args()
    print(json.dumps(parity(args.hbctool_hasm,args.hermes_dec_hasm),indent=2))
