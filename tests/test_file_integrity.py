"""Tests for file integrity monitoring functionality."""

import hashlib
import json
import os
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_file_integrity.py", "/src"))

from hids_mcp.server import (
    check_file_integrity,
    get_file_hash,
    CRITICAL_FILES,
)


class TestGetFileHash:
    """Tests for get_file_hash helper function."""

    def test_hash_existing_file(self, temp_dir):
        """Test hashing an existing file."""
        test_file = temp_dir / "test.txt"
        content = "test content for hashing"
        test_file.write_text(content)

        result = get_file_hash(str(test_file))

        expected = hashlib.sha256(content.encode()).hexdigest()
        assert result == expected

    def test_hash_binary_file(self, temp_dir):
        """Test hashing a binary file."""
        test_file = temp_dir / "binary.bin"
        content = bytes([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE])
        test_file.write_bytes(content)

        result = get_file_hash(str(test_file))

        expected = hashlib.sha256(content).hexdigest()
        assert result == expected

    def test_hash_nonexistent_file(self):
        """Test hashing a non-existent file returns None."""
        result = get_file_hash("/nonexistent/file.txt")
        assert result is None

    def test_hash_empty_file(self, temp_dir):
        """Test hashing an empty file."""
        test_file = temp_dir / "empty.txt"
        test_file.write_text("")

        result = get_file_hash(str(test_file))

        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_hash_large_file(self, temp_dir):
        """Test hashing a larger file."""
        test_file = temp_dir / "large.txt"
        content = "x" * 1000000  # 1MB of data
        test_file.write_text(content)

        result = get_file_hash(str(test_file))

        expected = hashlib.sha256(content.encode()).hexdigest()
        assert result == expected


class TestCheckFileIntegrity:
    """Tests for check_file_integrity function."""

    @pytest.mark.asyncio
    async def test_check_existing_files(self, critical_files):
        """Test integrity check on existing files."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        assert data["success"] is True
        assert data["files_checked"] == len(files_list)
        assert data["missing_files"] == 0

    @pytest.mark.asyncio
    async def test_check_returns_hashes(self, critical_files):
        """Test that current hashes are returned."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        assert "current_hashes" in data
        for filepath in files_list:
            assert filepath in data["current_hashes"]
            # Hash should be 64 char hex string
            assert len(data["current_hashes"][filepath]) == 64

    @pytest.mark.asyncio
    async def test_check_file_metadata(self, critical_files):
        """Test that file metadata is captured."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        for file_result in data["results"]:
            if file_result["exists"]:
                assert "size" in file_result
                assert "modified" in file_result
                assert "permissions" in file_result
                assert "sha256" in file_result

    @pytest.mark.asyncio
    async def test_check_missing_files(self, temp_dir):
        """Test handling of missing files."""
        missing_files = [
            str(temp_dir / "missing1.txt"),
            str(temp_dir / "missing2.txt"),
        ]
        result = await check_file_integrity(files=missing_files)
        data = json.loads(result)

        assert data["success"] is True
        assert data["missing_files"] == 2
        assert len(data["alerts"]) == 2

        # Check alert structure
        for alert in data["alerts"]:
            assert alert["type"] == "file_missing"
            assert alert["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_check_with_baseline_unchanged(self, critical_files, file_integrity_baseline):
        """Test integrity check with baseline - no changes."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(
            files=files_list,
            baseline_path=str(file_integrity_baseline)
        )
        data = json.loads(result)

        assert data["success"] is True
        assert data["changed_files"] == 0
        assert data["baseline_used"] is True

        # All files should show OK status
        for file_result in data["results"]:
            if file_result["exists"]:
                assert file_result["status"] == "OK"

    @pytest.mark.asyncio
    async def test_check_with_baseline_changed(self, modified_files):
        """Test integrity check detects changes from baseline."""
        files_list = list(modified_files["files"].values())
        result = await check_file_integrity(
            files=files_list,
            baseline_path=modified_files["baseline"]
        )
        data = json.loads(result)

        assert data["success"] is True
        assert data["changed_files"] == 2  # passwd and sshd_config modified
        assert len(data["alerts"]) >= 2

        # Check for high severity alerts on changed files
        change_alerts = [a for a in data["alerts"] if a["type"] == "file_changed"]
        assert len(change_alerts) == 2
        for alert in change_alerts:
            assert alert["severity"] == "high"

    @pytest.mark.asyncio
    async def test_check_no_baseline(self, critical_files):
        """Test integrity check without baseline shows NO_BASELINE."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        assert data["success"] is True
        assert data["baseline_used"] is False

        # All files should show NO_BASELINE status
        for file_result in data["results"]:
            if file_result["exists"]:
                assert file_result["status"] == "NO_BASELINE"

    @pytest.mark.asyncio
    async def test_check_invalid_baseline_path(self, critical_files):
        """Test handling of invalid baseline path."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(
            files=files_list,
            baseline_path="/nonexistent/baseline.json"
        )
        data = json.loads(result)

        # Should succeed but not use baseline
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_check_mixed_files(self, temp_dir, critical_files):
        """Test check with mix of existing and missing files."""
        existing = list(critical_files.values())[:2]
        missing = [str(temp_dir / "missing.txt")]

        result = await check_file_integrity(files=existing + missing)
        data = json.loads(result)

        assert data["success"] is True
        assert data["files_checked"] == 3
        assert data["missing_files"] == 1

    @pytest.mark.asyncio
    async def test_check_default_critical_files(self):
        """Test check uses default critical files when none specified."""
        result = await check_file_integrity()
        data = json.loads(result)

        # Should check some files (may not exist on test system)
        assert data["success"] is True
        assert data["files_checked"] > 0


class TestFileIntegrityAlerts:
    """Tests for file integrity alert generation."""

    @pytest.mark.asyncio
    async def test_alert_on_modified_file(self, modified_files):
        """Test alert generation for modified files."""
        files_list = list(modified_files["files"].values())
        result = await check_file_integrity(
            files=files_list,
            baseline_path=modified_files["baseline"]
        )
        data = json.loads(result)

        change_alerts = [a for a in data["alerts"] if a["type"] == "file_changed"]
        assert len(change_alerts) >= 1

        # Alert should include file path
        for alert in change_alerts:
            assert "file" in alert

    @pytest.mark.asyncio
    async def test_alert_on_missing_file(self, temp_dir):
        """Test alert generation for missing files."""
        result = await check_file_integrity(files=[str(temp_dir / "missing.txt")])
        data = json.loads(result)

        missing_alerts = [a for a in data["alerts"] if a["type"] == "file_missing"]
        assert len(missing_alerts) == 1
        assert missing_alerts[0]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_no_alert_on_unchanged_file(self, critical_files, file_integrity_baseline):
        """Test no alerts for unchanged files."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(
            files=files_list,
            baseline_path=str(file_integrity_baseline)
        )
        data = json.loads(result)

        assert len(data["alerts"]) == 0


class TestFileIntegrityResults:
    """Tests for file integrity result structure."""

    @pytest.mark.asyncio
    async def test_result_structure(self, critical_files):
        """Test result structure for each file."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        for file_result in data["results"]:
            assert "file" in file_result
            assert "exists" in file_result
            assert "status" in file_result

    @pytest.mark.asyncio
    async def test_existing_file_details(self, critical_files):
        """Test details for existing files."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        for file_result in data["results"]:
            if file_result["exists"]:
                assert "size" in file_result
                assert "modified" in file_result
                assert "permissions" in file_result
                assert "sha256" in file_result
                assert file_result["size"] >= 0

    @pytest.mark.asyncio
    async def test_permissions_format(self, critical_files):
        """Test permissions are in octal format."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        for file_result in data["results"]:
            if file_result["exists"]:
                perms = file_result["permissions"]
                # Should be 3 digit octal string
                assert len(perms) == 3
                assert all(c in "01234567" for c in perms)

    @pytest.mark.asyncio
    async def test_modified_timestamp_format(self, critical_files):
        """Test modified timestamp is ISO format."""
        files_list = list(critical_files.values())
        result = await check_file_integrity(files=files_list)
        data = json.loads(result)

        from datetime import datetime

        for file_result in data["results"]:
            if file_result["exists"]:
                # Should be parseable as ISO format
                datetime.fromisoformat(file_result["modified"])


class TestCriticalFilesConfiguration:
    """Tests for CRITICAL_FILES configuration."""

    def test_critical_files_defined(self):
        """Test that CRITICAL_FILES is defined."""
        assert isinstance(CRITICAL_FILES, list)
        assert len(CRITICAL_FILES) > 0

    def test_critical_files_are_absolute_paths(self):
        """Test that critical files are absolute paths."""
        for filepath in CRITICAL_FILES:
            assert filepath.startswith("/")

    def test_critical_files_include_key_files(self):
        """Test that key security files are included."""
        expected_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]

        for expected in expected_files:
            assert expected in CRITICAL_FILES
