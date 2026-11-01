"""Static completeness and schema audit of all HBC-Tool version modules.

Produces inspectable evidence; does not claim execution fidelity. Must run
against the SHA-pinned patched source tree from vibe_hbc_patch_all.py.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
import sys
from vibe_hbc_patch_all import VERSIONS

ALLOWED={"Reg8","Reg32","UInt8","UInt16","UInt32","Addr8",
         "Addr32","Imm32","Double"}

def reject_duplicates(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON mapping key: "+key)
        result[key]=value
    return result

def audit(root:Path)->dict:
    root=root.resolve()
    rows=[]
    total_files=0
    for version in VERSIONS:
        directory=root/"hbctool"/"hbc"/f"hbc{version}"
        sources=[]
        for filename in ("__init__.py","parser.py","translator.py"):
            path=directory/filename
            source=path.read_text("utf-8")
            ast.parse(source,filename=str(path))
            sources.append(source)
            total_files+=1
        op=json.loads((directory/"data"/"opcode.json").read_text("utf-8"),
                      object_pairs_hook=reject_duplicates)
        structure=json.loads((directory/"data"/"structure.json").read_text("utf-8"),
                             object_pairs_hook=reject_duplicates)
        if not 1<=len(op)<=256:
            raise ValueError(f"Unexpected opcode mapping size for HBC{version}")
        if not isinstance(structure.get("header"),dict):
            raise ValueError(f"No parsed header schema for HBC{version}")
        types={x.removesuffix(":S") for spec in op.values() for x in spec}
        if unknown:=types-ALLOWED:
            raise ValueError(f"Unknown operand types in HBC{version}: {unknown}")
        if "def getVersion(self):" not in sources[0]:
            raise ValueError(f"No version getter in HBC{version}")
        bigint="bigIntStorageSize" in structure["header"]
        parser_bigint="bigIntStorage" in sources[1]
        rows.append({"version":version,"opcode_count":len(op),
          "python_modules":3,"bigint_header_declared":bigint,
          "bigint_payload_consumption_seen":parser_bigint,
          "parser_assert_count":sources[1].count("assert "),
          "parser_todo_fixme_count":sources[1].count("TODO")+sources[1].count("FIXME")})
    report={"registered_versions":len(rows),"python_modules_compiled":total_files,
       "opcode_mappings_validated":len(rows),
       "binary_roundtrip_semantics":"not_proven_by_static_audit",
       "versions_with_unconsumed_bigint_header":[r["version"] for r in rows
          if r["bigint_header_declared"] and not r["bigint_payload_consumption_seen"]],
       "rows":rows}
    return report

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: python vibe_hbc_source_audit.py CHECKOUT")
    print(json.dumps(audit(Path(sys.argv[1])),indent=2))
