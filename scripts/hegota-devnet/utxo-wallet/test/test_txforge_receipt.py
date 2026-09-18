import importlib.util
import pathlib
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).parents[1] / "api" / "txforge.py"
SPEC = importlib.util.spec_from_file_location("txforge", MODULE_PATH)
txforge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(txforge)


class ReorgRpc(txforge.Rpc):
    TX_HASH = "0x" + "11" * 32
    ORPHAN_HASH = "0x" + "22" * 32
    CANONICAL_HASH = "0x" + "33" * 32

    def __init__(self):
        super().__init__("unused")
        self.receipt_calls = 0
        self.block_calls = 0
        self.resubmissions = 0

    def call(self, method, params):
        if method == "eth_getTransactionReceipt":
            self.receipt_calls += 1
            block_hash = self.ORPHAN_HASH if self.receipt_calls == 1 else self.CANONICAL_HASH
            return {"blockNumber": "0x64", "blockHash": block_hash}
        if method == "eth_getBlockByNumber":
            self.block_calls += 1
            # The first receipt points at a block that has already been replaced.
            return {"hash": self.CANONICAL_HASH}
        if method == "eth_sendRawTransaction":
            self.resubmissions += 1
            return self.TX_HASH
        if method == "eth_blockNumber":
            return "0x67"  # block 100 plus three canonical children
        raise AssertionError(f"unexpected RPC method {method}")


class ReceiptConfirmationTests(unittest.TestCase):
    @patch.object(txforge.time, "sleep", return_value=None)
    def test_orphaned_receipt_is_resubmitted_and_confirmed(self, _sleep):
        rpc = ReorgRpc()
        receipt = rpc.wait_receipt(
            rpc.TX_HASH,
            confirmations=3,
            raw_tx="0x06c0",
        )

        self.assertEqual(receipt["blockHash"], rpc.CANONICAL_HASH)
        self.assertEqual(rpc.resubmissions, 1)
        self.assertEqual(rpc.last_wait_meta["confirmations"], 3)
        self.assertEqual(rpc.last_wait_meta["confirmedAtHead"], 103)
        self.assertEqual(rpc.last_wait_meta["reorgs"], 1)
        self.assertEqual(rpc.last_wait_meta["resubmissions"], 1)


if __name__ == "__main__":
    unittest.main()
