"""Bounded HASM reference index regression cases."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from vibe_hermes_index import function_index

class IndexTests(unittest.TestCase):
    SAMPLE=("Function<alpha>0(1 params, 2 registers, 1 numbers, 0 non-pointers):\n"
      "\tLoadConstString      \tReg8:0, UInt16:7\n"
      "\t; Oper[1]: String(7) 'needle'\n"
      "\tCall                 \tReg8:0, Reg8:1\n"
      "EndFunction\n\n"
      "Function<beta>1(0 params, 2 registers, 0 numbers, 0 non-pointers):\n"
      "\t; Oper[0]: String(7) 'duplicate'\n"
      "EndFunction\n\n")

    def test_function_and_explicit_string_refs(self):
        r=function_index(self.SAMPLE)
        self.assertEqual(r["function_count"],2)
        self.assertEqual(r["references_scanned"],2)
        self.assertEqual(r["functions"][0]["instruction_count"],2)
        self.assertEqual(r["functions"][0]["string_refs"],[7])

    def test_duplicate_id_rejected(self):
        src=self.SAMPLE+self.SAMPLE.split("Function<beta>")[0]
        with self.assertRaises(ValueError): function_index(src)

    def test_cap_limits(self):
        result=function_index(self.SAMPLE,max_functions=1,max_references=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["function_count"],1)

    def test_long_line_skipped(self):
        r=function_index(self.SAMPLE+"\t"+"Z"*9000)
        self.assertTrue(r["truncated"])

    def test_empty_and_invalid_budgets(self):
        self.assertEqual(function_index("")["function_count"],0)
        for f,r in ((0,1),(2001,1),(1,-1),(1,10001)):
            with self.assertRaises(ValueError): function_index("",max_functions=f,max_references=r)

if __name__=="__main__":
    unittest.main()
