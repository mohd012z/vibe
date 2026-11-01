"""Opcode sequence parity parser tests; no genuine runtime claims."""
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from vibe_hbc_opcode_parity import parity,parse

class ParityTests(unittest.TestCase):
    def fixture(self,tool:str,p1:str):
        tmp=tempfile.TemporaryDirectory()
        root=Path(tmp.name)
        a,b=root/"h.hasm",root/"p1.hasm"
        a.write_text(tool)
        b.write_text(p1)
        return tmp,a,b

    def test_opcode_order_equal(self):
        t,a,b=self.fixture(
            "Function<test>0(1 params, 4 registers):\n"
            "\tNop                 \t\n"
            "\tLoadConstString     \tReg8:1, UInt16:7\nEndFunction\n",
            '=> [Function #0 "test" of 5 bytes]:\nBytecode listing:\n'
            '==> 00000000: <Nop>:\n'
            '==> 00000001: <LoadConstString>: <Reg8: 1, string_id: 7>\n')
        try:
            result=parity(a,b)
            self.assertTrue(result["opcode_name_sequence_equal"])
            self.assertEqual(result["hbctool_opcodes"],2)
            self.assertEqual(result["hermes_dec_opcodes"],2)
        finally:t.cleanup()

    def test_instruction_mismatch_reported(self):
        t,a,b=self.fixture(
            "Function<test>0(0 params):\n\tNop                 \t\nEndFunction\n",
            '=> [Function #0 "test" of 2 bytes]:\n'
            '==> 00000000: <Return>:\n')
        try:
            result=parity(a,b)
            self.assertFalse(result["opcode_name_sequence_equal"])
            self.assertEqual(result["first_mismatches"][0]["function_id"],0)
        finally:t.cleanup()

    def test_official_hbcdump_ncfunction_records(self):
        t,a,b=self.fixture(
            "Function<x>0(0 params):\nEndFunction\n",
            "Function<global>0(0 params):\n"
            "[@ 0] Nop\n"
            "NCFunction<helper>1(0 params):\n"
            "[@ 0] Return\n")
        try:
            result=parse(b,"official_hbcdump")
            self.assertEqual(len(result),2)
            self.assertEqual(result[0],("Nop",))
            self.assertEqual(result[1],("Return",))
        finally:t.cleanup()

    def test_unsupported_duplicate_function_rejected(self):
        t,a,b=self.fixture(
            "Function<test>0(0 params):\nEndFunction\n"
            "Function<test>0(0 params):\nEndFunction\n",
            '=> [Function #0 "test" of 0 bytes]:\n')
        try:
            with self.assertRaises(ValueError):
                parse(a,"hbctool")
        finally:t.cleanup()

if __name__=="__main__":
    unittest.main()
