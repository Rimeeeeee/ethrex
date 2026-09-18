import importlib.util
import pathlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "wallet_api", pathlib.Path(__file__).parents[1] / "api" / "[...path].py"
)
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)
KEY_A, KEY_B = "0x" + "11" * 32, "0x" + "22" * 32
ADDRESS_A, ADDRESS_B = "0x" + "11" * 20, "0x" + "22" * 20


def fake_forge(command):
    key = command.get("key") or command["actorKeys"][0]
    if command["op"] == "addressOf":
        return {"address": "0x" + key[-40:]}
    return {"status": "0x1", "txHash": "0x" + "aa" * 32}


class WalletIsolationTests(unittest.TestCase):
    def setUp(self):
        self.forge = patch.object(api, "forge", side_effect=fake_forge).start()
        self.rpc = patch.object(api, "rpc_call", return_value="0x1").start()
        self.addCleanup(patch.stopall)

    def request(self, method, path, body=None, headers=None):
        return api.handle_request(method, path, headers or {}, body)

    def test_imports_do_not_configure_other_visitors_or_retain_keys(self):
        for key, address in [(KEY_A, ADDRESS_A), (KEY_B, ADDRESS_B)]:
            result = self.request("POST", "/api/import", {"key": key})
            self.assertEqual(result, {"configured": True, "address": address})
        anonymous = self.request("GET", "/api/status")
        self.assertFalse(anonymous["configured"])
        self.assertIsNone(anonymous["address"])
        for address in [ADDRESS_A, ADDRESS_B]:
            result = self.request("GET", "/api/status", headers={"x-wallet-address": address})
            self.assertEqual(result["address"], address)

    def test_lock_does_not_affect_another_wallet_and_signing_requires_key(self):
        self.request("POST", "/api/import", {"key": KEY_A})
        self.request("POST", "/api/lock")
        for path in ["/api/deposit", "/api/send", "/api/redeem"]:
            with self.assertRaisesRegex(ValueError, "connect a wallet first"):
                self.request("POST", path, {}, {"x-wallet-address": ADDRESS_A})
        result = self.request("POST", "/api/deposit", {
            "key": KEY_B, "recipient": ADDRESS_A, "valueWei": "1"
        })
        self.assertEqual(result["source"], ADDRESS_B)

    def test_concurrent_deposits_keep_their_own_signer_and_rpc(self):
        barrier = threading.Barrier(2)
        signed = []

        def forge(command):
            if command["op"] == "addressOf":
                barrier.wait(timeout=5)
            else:
                signed.append((command["key"], api.request_rpc.get()))
            return fake_forge(command)

        self.forge.side_effect = forge
        initial_rpc = api.request_rpc.get()
        with ThreadPoolExecutor(max_workers=2) as executor:
            jobs = [executor.submit(self.request, "POST", "/api/deposit", {
                "key": key, "recipient": ADDRESS_A, "valueWei": "1"
            }, {"x-utxo-rpc": rpc}) for key, rpc in [
                (KEY_A, "https://alice.invalid"), (KEY_B, "https://bob.invalid")
            ]]
            results = [job.result(timeout=10) for job in jobs]
        self.assertEqual([r["source"] for r in results], [ADDRESS_A, ADDRESS_B])
        self.assertCountEqual(signed, [
            (KEY_A, "https://alice.invalid"), (KEY_B, "https://bob.invalid")
        ])
        self.assertEqual(api.request_rpc.get(), initial_rpc)

    def test_rpc_settings_and_failures_do_not_change_other_requests(self):
        initial_rpc = api.request_rpc.get()
        self.request("POST", "/api/rpc", {"url": "https://alice.invalid"})
        self.assertEqual(self.request("GET", "/api/status")["rpc"], initial_rpc)
        self.rpc.side_effect = RuntimeError("offline")
        with self.assertRaisesRegex(ValueError, "did not respond"):
            self.request("POST", "/api/rpc", {"url": "https://bob.invalid"})
        self.assertEqual(api.request_rpc.get(), initial_rpc)

    def test_cannot_spend_another_wallets_input(self):
        with self.assertRaisesRegex(ValueError, "belongs to"):
            self.request("POST", "/api/send", {
                "key": KEY_B, "recipient": ADDRESS_B, "valueWei": "1",
                "inputs": [{"index": 1, "creationBlock": 1, "source": ADDRESS_A,
                            "recipient": ADDRESS_A, "valueWei": "10"}]
            })
        self.assertTrue(all(c.args[0]["op"] == "addressOf" for c in self.forge.call_args_list))


if __name__ == "__main__":
    unittest.main()
