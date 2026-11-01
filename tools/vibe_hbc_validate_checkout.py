"""Execute checks against already-patched, pinned HBC-Tool source checkout."""
import argparse
import io
from pathlib import Path
import sys
import types

def verify(root: Path):
    sys.path.insert(0,str(root.resolve()))
    docopt=types.ModuleType("docopt")
    docopt.docopt=lambda *a,**k: {}
    sys.modules.setdefault("docopt",docopt)
    import hbctool.hbc as hbc
    from hbctool.util import BitWriter
    found=sorted(hbc.HBC)
    expected=[59,62,74,76,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100]
    assert found==expected,(found,expected)
    for version in found:
        obj=hbc.HBC[version]()
        assert obj.getVersion()==version,version
        def obj_for(length=4,utf16=False,offset=0,storage=None):
            obj.setObj({"header":{"stringCount":1},
              "stringTableEntries":[{"isUTF16":int(utf16),"offset":offset,"length":length}],
              "stringTableOverflowEntries":[],
              "stringStorage":storage if storage is not None else [65]* (length*(2 if utf16 else 1))})
            return obj.getObj()["stringStorage"]
        storage=obj_for()
        obj.setString(0,"éé")
        assert bytes(storage)=="éé".encode(),version
        for invalid in ("x","abc","abcdef","ééé",None,123):
            before=bytes(storage)
            try: obj.setString(0,invalid)
            except (ValueError,TypeError): pass
            else: raise AssertionError(f"HBC{version} accepted invalid {invalid!r}")
            assert before==bytes(storage)
        storage=obj_for(length=2,utf16=True)
        obj.setString(0,"41004200")
        assert bytes(storage)==b"A\x00B\x00"
        for invalid in ("4100","410042004300","fff", "gggg"):
            before=bytes(storage)
            try: obj.setString(0,invalid)
            except ValueError: pass
            else: raise AssertionError(f"HBC{version} accepted invalid UTF16")
            assert bytes(storage)==before
        obj_for(length=4,offset=3,storage=[0]*4)
        try: obj.setString(0,"ABCD")
        except ValueError: pass
        else: raise AssertionError(f"HBC{version} accepted out of bounds")
    stream=io.BytesIO()
    w=BitWriter(stream)
    w.write_bits(5,3)
    assert w.tell()==0
    w.align()
    assert w.tell()==1 and stream.getvalue()==bytes([5])
    w.pad(4)
    assert w.tell()==4 and stream.getvalue()==bytes([5,0,0,0])
    w.write_bits(15,4); w.write_bits(10,4)
    assert w.tell()==5 and stream.getvalue()==bytes([5,0,0,0,0xaf])
    w.flush()
    assert w.tell()==5
    print(f"PASS: {len(found)} module getters, Unicode/bounds tests, BitWriter accounting")

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("root",type=Path)
    opts=a.parse_args()
    verify(opts.root)
