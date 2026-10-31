#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) for FinSight AI."""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_LINE_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)\s*(?:;.*)?$")


def parse_python_requirements_lock(lock_path: Path) -> list[dict[str, str]]:
    """Parse pinned Python packages from a requirements.lock file."""
    if not lock_path.is_file():
        return []

    packages: list[dict[str, str]] = []
    seen: set[str] = set()

    for line in lock_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_LINE_PATTERN.match(line)
        if match:
            name, version = match.group(1), match.group(2)
            normalized = name.lower()
            if normalized not in seen:
                seen.add(normalized)
                packages.append({"name": name, "version": version})

    return sorted(packages, key=lambda p: p["name"].lower())


def parse_npm_package_lock(lock_path: Path) -> list[dict[str, Any]]:
    """Parse installed Node.js packages from a v2/v3 package-lock.json file."""
    if not lock_path.is_file():
        return []

    data = json.loads(lock_path.read_text(encoding="utf-8"))
    packages_map = data.get("packages", {})
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for key, info in packages_map.items():
        if not key or not key.startswith("node_modules/"):
            continue

        # Extract package name (handles nested node_modules e.g. node_modules/foo/node_modules/bar)
        parts = key.split("node_modules/")
        pkg_name = parts[-1]
        version = info.get("version")
        if not pkg_name or not version:
            continue

        key_tuple = (pkg_name, version)
        if key_tuple in seen:
            continue
        seen.add(key_tuple)

        comp: dict[str, Any] = {
            "name": pkg_name,
            "version": version,
            "license": info.get("license"),
            "is_dev": bool(info.get("dev")),
            "integrity": info.get("integrity"),
        }
        components.append(comp)

    return sorted(components, key=lambda c: (c["name"].lower(), c["version"]))


def generate_cyclonedx_sbom(
    version: str,
    commit_sha: str | None = None,
    backend_lock: Path | None = None,
    frontend_lock: Path | None = None,
) -> dict[str, Any]:
    """Generate CycloneDX 1.5 JSON formatted SBOM representation."""
    if backend_lock is None:
        backend_lock = ROOT / "apps/api/requirements.lock"
    if frontend_lock is None:
        frontend_lock = ROOT / "apps/web/package-lock.json"

    components: list[dict[str, Any]] = []

    # 1. Backend Python packages
    python_pkgs = parse_python_requirements_lock(backend_lock)
    for pkg in python_pkgs:
        purl = f"pkg:pypi/{pkg['name']}@{pkg['version']}"
        components.append(
            {
                "type": "library",
                "name": pkg["name"],
                "version": pkg["version"],
                "purl": purl,
                "scope": "required",
                "bom-ref": purl,
            }
        )

    # 2. Frontend Node.js packages
    npm_pkgs = parse_npm_package_lock(frontend_lock)
    for pkg in npm_pkgs:
        purl = f"pkg:npm/{pkg['name']}@{pkg['version']}"
        comp: dict[str, Any] = {
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": purl,
            "scope": "optional" if pkg.get("is_dev") else "required",
            "bom-ref": purl,
        }
        if pkg.get("license"):
            comp["licenses"] = [{"license": {"id": pkg["license"]}}]
        integrity = pkg.get("integrity")
        if integrity and isinstance(integrity, str):
            if integrity.startswith("sha512-"):
                b64_hash = integrity[len("sha512-") :]
                try:
                    hex_hash = base64.b64decode(b64_hash).hex()
                    comp["hashes"] = [{"alg": "SHA-512", "content": hex_hash}]
                except Exception:
                    pass
        components.append(comp)

    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    serial_urn = f"urn:uuid:{uuid.uuid4()}"

    metadata_component: dict[str, Any] = {
        "type": "application",
        "name": "finsight-ai",
        "version": version,
        "description": "FinSight AI quantitative financial research and intelligence platform",
    }
    if commit_sha:
        metadata_component["properties"] = [
            {"name": "git:commit_sha", "value": commit_sha}
        ]

    sbom: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_urn,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "FinSight AI",
                    "name": "generate_sbom.py",
                    "version": "1.0.0",
                }
            ],
            "component": metadata_component,
        },
        "components": components,
    }
    return sbom


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=ROOT / "dist" / "finsight-sbom.json",
        help="Path where output JSON SBOM will be written",
    )
    parser.add_argument(
        "--version",
        default="0.1.0",
        help="Release version string (default: 0.1.0)",
    )
    parser.add_argument(
        "--commit-sha",
        default=None,
        help="Git commit SHA for metadata attribution",
    )
    parser.add_argument(
        "--backend-lock",
        type=Path,
        default=ROOT / "apps/api/requirements.lock",
        help="Path to backend requirements.lock",
    )
    parser.add_argument(
        "--frontend-lock",
        type=Path,
        default=ROOT / "apps/web/package-lock.json",
        help="Path to frontend package-lock.json",
    )
    args = parser.parse_args()

    sbom = generate_cyclonedx_sbom(
        version=args.version,
        commit_sha=args.commit_sha,
        backend_lock=args.backend_lock,
        frontend_lock=args.frontend_lock,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    print(f"Generated CycloneDX 1.5 JSON SBOM with {len(sbom['components'])} components at: {args.output}")


if __name__ == "__main__":
    main()
