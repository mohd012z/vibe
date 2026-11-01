"""Compare third-party opcode lists with Hermes hbcdump reference text.

Only uses pinned public fixture outputs, never treats those cached outputs as
runtime execution proof. Verifies version and source hash before comparing.
"""
from __future__ import annotations
from pathlib import Path
from vibe_hbc_opcode_parity import parse

def compare_to_official(original:bytes,hbctool_path:Path,hermes_dec_path:Path,
                        official_path:Path)->dict:
    if not official_path.is_file() or official_path.is_symlink():
        return {"status":"official_listing_unavailable"}
    raw=official_path.read_text("utf-8",errors="replace")
    version=int.from_bytes(original[8:12],"little")
    source_hash=original[12:32].hex()
    if f"Bytecode version number: {version}" not in raw or f"Source hash: {source_hash}" not in raw:
        return {"status":"oracle_provenance_mismatch"}
    official=parse(official_path,"official_hbcdump")
    hbctool=parse(hbctool_path,"hbctool")
    p1=parse(hermes_dec_path,"hermes_dec")
    def stats(other:dict[int,tuple[str,...]])->dict:
        ids=set(official)|set(other)
        disagree=[fid for fid in sorted(ids) if official.get(fid)!=other.get(fid)]
        return {
            "functions":len(other),
            "opcodes":sum(map(len,other.values())),
            "functions_disagreeing":len(disagree),
            "first_disagreeing_ids":disagree[:10],
            "opcode_sequence_identical":not disagree
        }
    return {"status":"compared",
            "official_functions":len(official),
            "official_opcodes":sum(map(len,official.values())),
            "hbctool":stats(hbctool),
            "hermes_dec":stats(p1),
            "semantic_equivalence":"not_tested"}
