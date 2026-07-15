#!/usr/bin/env python3
"""Focused QA for scripts/testnet/synergy-rpc-router.py."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


SCRIPT = Path(__file__).parents[1] / "testnet" / "synergy-rpc-router.py"
SPEC = importlib.util.spec_from_file_location("synergy_rpc_router", SCRIPT)
assert SPEC and SPEC.loader
router_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = router_module
SPEC.loader.exec_module(router_module)


class FakeRPCHandler(BaseHTTPRequestHandler):
    responses: dict[str, Any] = {}
    requests: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        type(self).requests.append(request)
        result = type(self).responses.get(request["method"], {"ok": True})
        body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def fake_server(responses: dict[str, Any]) -> tuple[ThreadingHTTPServer, str]:
    FakeRPCHandler.responses = responses
    FakeRPCHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeRPCHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}/"


def isolated_fake_server(responses: dict[str, Any]) -> tuple[ThreadingHTTPServer, str, list[dict[str, Any]]]:
    requests: list[dict[str, Any]] = []

    class IsolatedFakeRPCHandler(FakeRPCHandler):
        pass

    IsolatedFakeRPCHandler.responses = responses
    IsolatedFakeRPCHandler.requests = requests
    server = ThreadingHTTPServer(("127.0.0.1", 0), IsolatedFakeRPCHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}/", requests


class RouterTests(unittest.TestCase):
    def make_config(self, reads: tuple[str, ...], writes: tuple[str, ...], **overrides: Any) -> Any:
        values = {
            "bind_host": "127.0.0.1",
            "bind_port": 0,
            "read_upstreams": reads,
            "write_upstreams": writes,
            "local_fallback_url": None,
            "synid_local_source": None,
            "timeout_seconds": 0.25,
            "max_request_bytes": 1024,
            "max_response_bytes": 4096,
            "cache_ttl_seconds": 30.0,
            "cache_entries": 2,
            "failure_threshold": 1,
            "cooldown_seconds": 30.0,
        }
        values.update(overrides)
        return router_module.RouterConfig(**values)

    def test_read_failover_circuit_breaker_and_bounded_last_good_cache(self) -> None:
        server, url = fake_server({"synergy_getLatestBlock": {"height": 42}})
        try:
            closed = "http://127.0.0.1:1/"
            config = self.make_config((closed, url, url), (url,))
            router = router_module.Router(config)
            request = {"jsonrpc": "2.0", "id": 1, "method": "synergy_getLatestBlock", "params": []}
            first = router.route_one(request)
            self.assertEqual(first["result"]["height"], 42)
            server.shutdown()
            second = router.route_one({**request, "id": 2})
            self.assertEqual(second["id"], 2)
            self.assertEqual(second["result"]["height"], 42)
            self.assertEqual(router.metrics.snapshot()["rpc_cache_hits_total"], 1)
            self.assertEqual(router._states["read"][0].failures, 1)
        finally:
            server.server_close()

    def test_writes_use_write_pool_and_do_not_use_read_or_local_fallback(self) -> None:
        server, url = fake_server({"synergy_sendTransaction": {"accepted": True}})
        try:
            config = self.make_config(("http://127.0.0.1:1/",) * 3, (url,), local_fallback_url="http://127.0.0.1:1/")
            router = router_module.Router(config)
            response = router.route_one({"jsonrpc": "2.0", "id": 9, "method": "synergy_sendTransaction", "params": [{"x": 1}]})
            self.assertEqual(response["result"], {"accepted": True})
            self.assertEqual(FakeRPCHandler.requests[-1]["method"], "synergy_sendTransaction")
        finally:
            server.shutdown()
            server.server_close()

    def test_write_transport_failure_is_fail_closed_without_retry(self) -> None:
        server, url, requests = isolated_fake_server({"synergy_sendTransaction": {"accepted": True}})
        try:
            config = self.make_config(
                (url,) * 3,
                ("http://127.0.0.1:1/", url),
                local_fallback_url=url,
                failure_threshold=1,
            )
            router = router_module.Router(config)
            response = router.route_one(
                {"jsonrpc": "2.0", "id": 10, "method": "synergy_sendTransaction", "params": [{}]}
            )
            self.assertEqual(response["error"]["code"], -32001)
            self.assertEqual(requests, [])
            self.assertEqual(router.metrics.snapshot()["rpc_request_failures_total"], 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_reads_round_robin_across_three_distinct_relayers(self) -> None:
        servers = []
        urls = []
        logs = []
        try:
            for index in range(3):
                server, url, requests = isolated_fake_server(
                    {"synergy_getLatestBlock": {"relayer": index + 1}}
                )
                servers.append(server)
                urls.append(url)
                logs.append(requests)
            router = router_module.Router(self.make_config(tuple(urls), (urls[0],)))
            for request_id, expected in enumerate((1, 2, 3), start=1):
                response = router.route_one(
                    {"jsonrpc": "2.0", "id": request_id, "method": "synergy_getLatestBlock", "params": []}
                )
                self.assertEqual(response["result"]["relayer"], expected)
            self.assertEqual([len(log) for log in logs], [1, 1, 1])
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()

    def test_local_synid_source_preserves_registry_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synid_registry.json"
            path.write_text(json.dumps({"records": {}}), encoding="utf-8")
            valid_address = "synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r"
            server, url = fake_server({})
            try:
                router = router_module.Router(self.make_config((url,) * 3, (url,), synid_local_source=str(path)))
                register = router.route_one({
                    "jsonrpc": "2.0", "id": 1, "method": "synergy_registerSynID",
                    "params": [{"synId": "alice", "address": valid_address, "displayName": "Alice"}],
                })
                self.assertEqual(register["result"]["synId"], "alice.syn")
                resolve = router.route_one({"jsonrpc": "2.0", "id": 2, "method": "synergy_resolveSynID", "params": ["@alice"]})
                self.assertEqual(resolve["result"]["address"], valid_address)
                listing = router.route_one({"jsonrpc": "2.0", "id": 3, "method": "synergy_getAddressBook", "params": []})
                self.assertEqual(listing["result"]["records"][0]["syn_id"], "alice.syn")
                self.assertEqual(len(FakeRPCHandler.requests), 0)
            finally:
                server.shutdown()
                server.server_close()

    def test_local_synid_source_reads_legacy_camel_case_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synid_registry.json"
            path.write_text(
                json.dumps(
                    {
                        "records": {
                            "Alice": {
                                "address": "synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r",
                                "displayName": "Alice",
                                "createdAt": 7,
                                "updatedAt": 8,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            server, url = fake_server({})
            try:
                router = router_module.Router(
                    self.make_config((url,) * 3, (url,), synid_local_source=str(path))
                )
                resolved = router.route_one(
                    {"jsonrpc": "2.0", "id": 1, "method": "synergy_resolveSynID", "params": ["alice"]}
                )
                self.assertEqual(resolved["result"]["synId"], "alice.syn")
                self.assertEqual(resolved["result"]["createdAt"], 7)
                self.assertEqual(resolved["result"]["updatedAt"], 8)
            finally:
                server.shutdown()
                server.server_close()

    def test_synid_registry_size_limit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synid_registry.json"
            path.write_text("x" * 32, encoding="utf-8")
            router = router_module.Router(
                self.make_config(
                    ("http://127.0.0.1:1/",) * 3,
                    ("http://127.0.0.1:1/",),
                    synid_local_source=str(path),
                    max_synid_registry_bytes=16,
                )
            )
            response = router.route_one(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "synergy_registerSynID",
                    "params": [
                        {
                            "synId": "alice",
                            "address": "synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r",
                        }
                    ],
                }
            )
            self.assertEqual(response["error"]["code"], -32002)

    def test_config_rejects_fewer_than_three_read_upstreams(self) -> None:
        old = dict(os.environ)
        try:
            os.environ["SYNERGY_RPC_READ_UPSTREAMS"] = "http://127.0.0.1:1/,http://127.0.0.1:2/"
            os.environ["SYNERGY_RPC_WRITE_UPSTREAMS"] = "http://127.0.0.1:3/"
            with self.assertRaises(router_module.RouterConfigError):
                router_module.RouterConfig.from_env()
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_config_rejects_duplicate_read_upstreams(self) -> None:
        old = dict(os.environ)
        try:
            os.environ["SYNERGY_RPC_READ_UPSTREAMS"] = "http://127.0.0.1:1/,http://127.0.0.1:1/,http://127.0.0.1:2/"
            os.environ["SYNERGY_RPC_WRITE_UPSTREAMS"] = "http://127.0.0.1:3/"
            with self.assertRaises(router_module.RouterConfigError):
                router_module.RouterConfig.from_env()
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_cache_eviction_and_degraded_health_are_visible(self) -> None:
        server, url = fake_server({})
        try:
            router = router_module.Router(self.make_config((url,) * 3, (url,), cache_entries=2))
            for index in range(3):
                router.route_one(
                    {"jsonrpc": "2.0", "id": index, "method": f"synergy_read_{index}", "params": []}
                )
            self.assertEqual(len(router._cache), 2)
            self.assertEqual(router.metrics.snapshot()["rpc_cache_evictions_total"], 1)
            for state in router._states["read"]:
                state.open_until = router.clock() + 60
            ready, details = router.health()
            self.assertFalse(ready)
            self.assertEqual(details["status"], "degraded")
            self.assertFalse(details["read_upstreams_ready"])
            self.assertTrue(details["write_upstreams_ready"])
        finally:
            server.shutdown()
            server.server_close()

    def test_health_metrics_and_http_request_limit(self) -> None:
        upstream, upstream_url = fake_server({"synergy_getLatestBlock": {"height": 7}})
        router_server = None
        try:
            router = router_module.Router(self.make_config((upstream_url,) * 3, (upstream_url,), max_request_bytes=64))
            router_server = router_module.RouterHTTPServer(("127.0.0.1", 0), router)
            thread = threading.Thread(target=router_server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{router_server.server_port}"
            with urlopen(f"{base}/healthz", timeout=1) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"ok\n")
            with urlopen(f"{base}/metrics", timeout=1) as response:
                metrics = response.read().decode()
                self.assertIn("synergy_rpc_router_info", metrics)
            oversized = Request(
                f"{base}/",
                data=b"{" + b"x" * 80 + b"}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as context:
                urlopen(oversized, timeout=1)
            self.assertEqual(context.exception.code, 413)
        finally:
            if router_server is not None:
                router_server.shutdown()
                router_server.server_close()
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    unittest.main()
