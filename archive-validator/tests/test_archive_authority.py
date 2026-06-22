import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "macos" / "archive-authority.py"
SPEC = importlib.util.spec_from_file_location("archive_authority", MODULE_PATH)
archive_authority = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(archive_authority)


class ArchiveAuthorityPolicyTests(unittest.TestCase):
    def test_default_worker_classes_are_current_role_classes_only(self) -> None:
        self.assertEqual(
            archive_authority.DEFAULT_WORKER_CLASSES,
            [
                "validator-pruned",
                "support-relayer",
                "support-observer",
                "indexer-replay",
                "support-rpc",
                "archive-full",
            ],
        )

    def test_current_role_class_cadence_and_retention(self) -> None:
        policy = archive_authority.CLASS_POLICY
        self.assertEqual(policy["archive-full"]["cadence"], 15_000)
        for snapshot_class in [
            "validator-pruned",
            "support-relayer",
            "support-observer",
            "indexer-replay",
            "support-rpc",
        ]:
            self.assertEqual(policy[snapshot_class]["cadence"], 5_000)
            self.assertEqual(policy[snapshot_class]["retain"], 2)

    def test_current_roles_have_default_snapshot_coverage(self) -> None:
        coverage = {
            role: snapshot_class
            for snapshot_class in archive_authority.DEFAULT_WORKER_CLASSES
            for role in archive_authority.CLASS_POLICY[snapshot_class]["roles"]
        }
        self.assertEqual(coverage["validator"], "validator-pruned")
        self.assertEqual(coverage["relayer"], "support-relayer")
        self.assertEqual(coverage["observer"], "support-observer")
        self.assertEqual(coverage["explorer_indexer"], "indexer-replay")
        self.assertEqual(coverage["rpc_gateway"], "support-rpc")
        self.assertEqual(coverage["archive_validator"], "archive-full")

    def test_prune_apply_enforces_two_per_class_without_retired_grace(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            publish_root = root / "published"
            publish_root.mkdir()
            removed_path = publish_root / "testnet-1264" / "support-observer" / "snapshot-000000100"
            removed_path.mkdir(parents=True)
            kept_path = publish_root / "testnet-1264" / "support-observer" / "snapshot-000000300"
            kept_path.mkdir(parents=True)
            archive_removed_path = publish_root / "testnet-1264" / "archive-full" / "snapshot-000010000"
            archive_removed_path.mkdir(parents=True)

            def entry(snapshot_class: str, height: int, local_path: Path, *, pinned: bool = False) -> dict:
                return {
                    "snapshot_id": f"snapshot-{height:09d}",
                    "snapshot_class": snapshot_class,
                    "height": height,
                    "status": "published",
                    "local_path": str(local_path),
                    "pinned": pinned,
                }

            catalog = {
                "schema": "synergy-archive-snapshot-catalog-v1",
                "chain_id": archive_authority.CHAIN_ID,
                "network_id": archive_authority.NETWORK_ID,
                "genesis_hash": archive_authority.GENESIS_HASH,
                "updated_at": 1,
                "snapshots": [
                    entry("support-observer", 100, removed_path, pinned=True),
                    entry("support-observer", 200, publish_root / "snapshot-000000200"),
                    entry("support-observer", 300, kept_path),
                    entry("archive-full", 10_000, archive_removed_path),
                    entry("archive-full", 25_000, publish_root / "snapshot-000025000"),
                    entry("archive-full", 40_000, publish_root / "snapshot-000040000"),
                ],
            }
            archive_authority.json_dump(publish_root / "catalog.json", catalog)

            original_writer = archive_authority.write_signed_catalog
            try:
                archive_authority.write_signed_catalog = lambda _aegis, _root, out, value: archive_authority.json_dump(
                    out / "catalog.json", value
                )
                result = archive_authority.prune(
                    SimpleNamespace(
                        publish_root=publish_root,
                        root=root,
                        aegis=Path("/does/not/matter"),
                        apply=True,
                    )
                )
            finally:
                archive_authority.write_signed_catalog = original_writer

            self.assertTrue(result["ok"])
            self.assertFalse(removed_path.exists())
            self.assertFalse(archive_removed_path.exists())
            self.assertTrue(kept_path.exists())
            pruned = json.loads((publish_root / "catalog.json").read_text(encoding="utf-8"))
            remaining = {
                (item["snapshot_class"], item["snapshot_id"])
                for item in pruned["snapshots"]
            }
            self.assertNotIn(("support-observer", "snapshot-000000100"), remaining)
            self.assertNotIn(("archive-full", "snapshot-000010000"), remaining)
            self.assertIn(("support-observer", "snapshot-000000300"), remaining)
            self.assertEqual(
                sum(1 for item in pruned["snapshots"] if item["snapshot_class"] == "support-observer"),
                2,
            )
            self.assertEqual(
                sum(1 for item in pruned["snapshots"] if item["snapshot_class"] == "archive-full"),
                2,
            )
            self.assertTrue(
                any(action.get("pinned_ignored_for_hard_cap") for action in result["actions"])
            )


if __name__ == "__main__":
    unittest.main()
