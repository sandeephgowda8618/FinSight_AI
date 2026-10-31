from __future__ import annotations

import json
import re
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_sbom_generation_valid_cyclonedx_json():
    """Verify scripts.generate_sbom generates a compliant CycloneDX 1.5 JSON SBOM."""
    from scripts.generate_sbom import generate_cyclonedx_sbom

    sbom = generate_cyclonedx_sbom(
        version="0.1.0",
        commit_sha="a" * 40,
        backend_lock=ROOT / "apps/api/requirements.lock",
        frontend_lock=ROOT / "apps/web/package-lock.json",
    )

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["version"] == 1

    metadata = sbom["metadata"]
    assert metadata["component"]["name"] == "finsight-ai"
    assert metadata["component"]["version"] == "0.1.0"
    assert metadata["component"]["type"] == "application"
    assert len(metadata["tools"]) >= 1

    components = sbom["components"]
    assert len(components) > 0

    # Ensure every component has mandatory CycloneDX fields
    for comp in components:
        assert comp["name"]
        assert comp["version"]
        assert comp["type"] == "library"
        assert comp["purl"]


def test_dependency_inventory_corresponds_to_shipped_build():
    """Verify that every package in requirements.lock and key frontend locks are in the SBOM."""
    from scripts.generate_sbom import generate_cyclonedx_sbom, parse_python_requirements_lock

    python_packages = parse_python_requirements_lock(ROOT / "apps/api/requirements.lock")
    assert len(python_packages) == 23

    sbom = generate_cyclonedx_sbom(
        version="0.1.0",
        backend_lock=ROOT / "apps/api/requirements.lock",
        frontend_lock=ROOT / "apps/web/package-lock.json",
    )

    purl_set = {comp["purl"] for comp in sbom["components"]}

    # Verify all 23 locked Python dependencies exist in the SBOM
    for pkg in python_packages:
        expected_purl = f"pkg:pypi/{pkg['name']}@{pkg['version']}"
        assert expected_purl in purl_set, f"Missing Python package {pkg['name']} in SBOM"

    # Verify core frontend dependencies exist
    for fe_name in ["next", "react", "react-dom"]:
        matching = [c for c in sbom["components"] if c["name"] == fe_name]
        assert len(matching) > 0, f"Missing frontend package {fe_name} in SBOM"


def test_release_packaging_includes_sbom_changelog_and_all_migrations():
    """Verify scripts.package_release bundles SBOM, CHANGELOG.md, and all migrations."""
    from scripts.package_release import package

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fake_frontend = tmp_path / "standalone"
        fake_frontend.mkdir()
        (fake_frontend / "server.js").write_text("// server.js", encoding="utf-8")

        fake_static = tmp_path / "static"
        fake_static.mkdir()
        (fake_static / "dummy.css").write_text("/* dummy */", encoding="utf-8")

        out_dir = tmp_path / "dist"
        commit_sha = "0123456789abcdef0123456789abcdef01234567"

        # Pass web_static_dir so the packaging test is hermetic even when frontend is not built
        with patch("scripts.package_release.ROOT", ROOT):
            artifact, checksum, build_info = package(
                frontend_dir=fake_frontend,
                version="0.1.0",
                commit_sha=commit_sha,
                output_dir=out_dir,
                web_static_dir=fake_static,
            )

            assert artifact.is_file()
            assert checksum.is_file()
            assert build_info.is_file()

            # Inspect tarball contents
            with tarfile.open(artifact, "r:gz") as tar:
                names = set(tar.getnames())
                assert "finsight/RELEASE-METADATA.json" in names
                assert "finsight/RELEASE_README.md" in names
                assert "finsight/CHANGELOG.md" in names
                assert "finsight/backend/requirements.lock" in names
                assert "finsight/backend/migrations/0007_user_connections.sql" in names

                # Verify metadata
                meta_file = tar.extractfile("finsight/RELEASE-METADATA.json")
                assert meta_file is not None
                meta = json.loads(meta_file.read().decode("utf-8"))
                assert "0007_user_connections.sql" in meta["database_migrations"]
                assert meta["version"] == "0.1.0"
                assert meta["commit_sha"] == commit_sha
                assert "dependency_inventory" in meta


def test_defect_registry_links_to_existing_regression_tests():
    """Verify that docs/release/DEFECT_REGISTRY.md exists and every defect links to an existing regression test."""
    defect_file = ROOT / "docs/release/DEFECT_REGISTRY.md"
    assert defect_file.is_file(), "DEFECT_REGISTRY.md must exist in docs/release/"

    content = defect_file.read_text(encoding="utf-8")
    assert "# FinSight AI — Defect Triage and Regression Traceability Registry" in content

    # Find table rows with defect IDs like DEF-001
    defect_rows = re.findall(r"\| *(DEF-\d+) *\| *([^|]+) *\| *([^|]+) *\| *([^|]+) *\| *([^|]+) *\| *([^|]+) *\|", content)
    assert len(defect_rows) >= 3, "At least 3 triage defects should be recorded"

    for defect_id, title, severity, status, story, test_ref in defect_rows:
        test_ref = test_ref.strip()
        assert test_ref, f"Defect {defect_id} must have a regression test reference"
        if "::" in test_ref:
            rel_file, func_name = test_ref.split("::", 1)
        else:
            rel_file, func_name = test_ref, None

        test_path = ROOT / rel_file.strip()
        assert test_path.is_file(), f"Regression test file {test_path} referenced by {defect_id} does not exist"

        if func_name:
            file_text = test_path.read_text(encoding="utf-8")
            assert f"def {func_name.strip()}(" in file_text, (
                f"Regression test function {func_name} referenced by {defect_id} not found in {rel_file}"
            )


def test_changelog_format_and_version_baseline():
    """Verify CHANGELOG.md exists at repository root, follows Keep a Changelog, and records 0.1.0."""
    changelog_file = ROOT / "CHANGELOG.md"
    assert changelog_file.is_file(), "CHANGELOG.md must exist at repository root"

    content = changelog_file.read_text(encoding="utf-8")
    assert "# Changelog" in content
    assert "Keep a Changelog" in content
    assert "Semantic Versioning" in content
    assert "## [0.1.0]" in content

    # Check required categories
    assert "### Added" in content
    assert "### Fixed" in content
    assert "### Security" in content

    # Confirm version matches package.json
    pkg_json = json.loads((ROOT / "apps/web/package.json").read_text(encoding="utf-8"))
    assert "0.1.0" == pkg_json["version"]
