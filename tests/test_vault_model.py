from datetime import datetime, timedelta, timezone
from uuid import UUID
import unittest

from luxcipher.vault_model import VAULT_SCHEMA_VERSION, VaultData, VaultEntry


class VaultModelTests(unittest.TestCase):
    def test_creates_entry_with_stable_identifier_and_timestamps(self) -> None:
        entry = VaultEntry.create(
            title="Email",
            username="matteo@example.com",
            password="correct horse battery staple",
            url="https://example.com",
            notes="Personal account",
        )

        UUID(entry.id)
        self.assertEqual(entry.title, "Email")
        self.assertEqual(entry.username, "matteo@example.com")
        self.assertEqual(entry.password, "correct horse battery staple")
        self.assertIsNotNone(entry.created_at.tzinfo)
        self.assertIsNotNone(entry.updated_at.tzinfo)

    def test_entry_requires_title_and_password(self) -> None:
        with self.assertRaises(ValueError):
            VaultEntry.create(title="", password="secret")

        with self.assertRaises(ValueError):
            VaultEntry.create(title="Email", password="")

    def test_entry_round_trips_through_dictionary(self) -> None:
        entry = VaultEntry.create(
            title="Email",
            username="matteo@example.com",
            password="secret",
        )

        restored = VaultEntry.from_dict(entry.to_dict())

        self.assertEqual(restored, entry)

    def test_empty_vault_uses_current_schema_version(self) -> None:
        vault = VaultData.empty()

        self.assertEqual(vault.schema_version, VAULT_SCHEMA_VERSION)
        self.assertEqual(vault.entries, ())
        self.assertIsNotNone(vault.created_at.tzinfo)
        self.assertIsNotNone(vault.updated_at.tzinfo)

    def test_vault_round_trips_entries_through_dictionary(self) -> None:
        entry = VaultEntry.create(title="Email", password="secret")
        vault = VaultData(entries=(entry,))

        restored = VaultData.from_dict(vault.to_dict())

        self.assertEqual(restored, vault)

    def test_vault_entries_are_stored_as_tuple(self) -> None:
        entry = VaultEntry.create(title="Email", password="secret")
        vault = VaultData(entries=[entry])

        self.assertEqual(vault.entries, (entry,))

    def test_rejects_unsupported_schema_version(self) -> None:
        with self.assertRaises(ValueError):
            VaultData(schema_version=VAULT_SCHEMA_VERSION + 1)

    def test_rejects_updated_at_before_created_at(self) -> None:
        created_at = datetime.now(timezone.utc)
        updated_at = created_at - timedelta(seconds=1)

        with self.assertRaises(ValueError):
            VaultEntry(
                id="b47d2b25-eaf2-4480-87e8-e554f136ea82",
                title="Email",
                password="secret",
                username="",
                created_at=created_at,
                updated_at=updated_at,
            )

    def test_rejects_naive_serialized_timestamps(self) -> None:
        entry = VaultEntry.create(title="Email", password="secret")
        data = entry.to_dict()
        data["createdAt"] = "2026-08-10T12:00:00"

        with self.assertRaises(ValueError):
            VaultEntry.from_dict(data)


if __name__ == "__main__":
    unittest.main()
