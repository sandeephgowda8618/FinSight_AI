#!/usr/bin/env python3
"""Build a versioned FinSight application bundle from locked/build outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_sbom import (
    generate_cyclonedx_sbom,
    parse_npm_package_lock,
    parse_python_requirements_lock,
)

VERSION_PATTERN = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z")
SHA_PATTERN = re.compile(r"\A[0-9a-f]{40}\Z")


def package(
    frontend_dir: Path,
    version: str,
    commit_sha: str | None,
    output_dir: Path,
    web_static_dir: Path | None = None,
) -> tuple[Path, Path, Path]:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("version must be a numeric semantic version, optionally with a prerelease/build suffix")
    if commit_sha and not SHA_PATTERN.fullmatch(commit_sha):
        raise ValueError("commit SHA must be a full 40-character lowercase hexadecimal SHA")
    if not frontend_dir.is_dir() or not (frontend_dir / "server.js").is_file():
        raise FileNotFoundError("frontend standalone build is missing server.js")

    web_static = web_static_dir if web_static_dir is not None else (ROOT / "apps/web/.next/static")
    runtime_config = ROOT / "apps/web/app/api/runtime-config/route.js"
    if not web_static.is_dir() or not runtime_config.is_file():
        raise FileNotFoundError("build the frontend before packaging")

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_base = f"finsight-{version}" + (f"-{commit_sha[:12]}" if commit_sha else "")

    # Generate CycloneDX SBOM
    backend_lock = ROOT / "apps/api/requirements.lock"
    frontend_lock = ROOT / "apps/web/package-lock.json"
    sbom = generate_cyclonedx_sbom(
        version=version,
        commit_sha=commit_sha,
        backend_lock=backend_lock,
        frontend_lock=frontend_lock,
    )
    sbom_filename = f"{artifact_base}-sbom.json"
    sbom_path = output_dir / sbom_filename
    sbom_content = json.dumps(sbom, indent=2) + "\n"
    sbom_path.write_text(sbom_content, encoding="utf-8")

    # Discover current database migrations dynamically
    migrations_dir = ROOT / "apps/api/migrations"
    migrations_list = sorted(f.name for f in migrations_dir.glob("*.sql")) if migrations_dir.is_dir() else []

    py_locked_count = len(parse_python_requirements_lock(backend_lock))
    npm_locked_count = len(parse_npm_package_lock(frontend_lock))

    with tempfile.TemporaryDirectory(prefix="finsight-release-") as temp_dir:
        payload = Path(temp_dir) / "finsight"
        frontend = payload / "frontend"
        shutil.copytree(frontend_dir, frontend, symlinks=True)
        shutil.copytree(web_static, frontend / ".next/static", symlinks=True)

        backend = payload / "backend"
        shutil.copytree(ROOT / "apps/api/app", backend / "app", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(ROOT / "apps/api/migrations", backend / "migrations")
        shutil.copy2(backend_lock, backend / "requirements.lock")

        metadata = {
            "artifact": artifact_base,
            "version": version,
            "commit_sha": commit_sha,
            "frontend": {"runtime": "Node.js 22", "entrypoint": "node frontend/server.js"},
            "backend": {"runtime": "Python 3.12", "entrypoint": "python -m uvicorn app.main:app"},
            "database_migrations": migrations_list,
            "dependency_inventory": {
                "python_locked_packages": py_locked_count,
                "npm_locked_packages": npm_locked_count,
                "total_sbom_components": len(sbom["components"]),
                "sbom_file": sbom_filename,
            },
            "changelog": "CHANGELOG.md",
            "configuration": "Runtime values are supplied through environment variables; see RELEASE_README.md.",
        }
        (payload / "RELEASE-METADATA.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        release_readme = ROOT / "docs/release/RELEASE_README.md"
        if release_readme.is_file():
            shutil.copy2(release_readme, payload / "RELEASE_README.md")

        changelog = ROOT / "CHANGELOG.md"
        if changelog.is_file():
            shutil.copy2(changelog, payload / "CHANGELOG.md")

        (payload / "SBOM.json").write_text(sbom_content, encoding="utf-8")

        artifact_path = output_dir / f"{artifact_base}.tar.gz"

        def normalized_member(member: tarfile.TarInfo) -> tarfile.TarInfo:
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            return member

        with artifact_path.open("wb") as raw:
            import gzip

            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for item in sorted(payload.rglob("*")):
                        archive.add(
                            item,
                            arcname=(Path("finsight") / item.relative_to(payload)).as_posix(),
                            recursive=False,
                            filter=normalized_member,
                        )

    digest_builder = hashlib.sha256()
    with artifact_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest_builder.update(chunk)
    digest = digest_builder.hexdigest()
    checksum_path = output_dir / f"{artifact_path.name}.sha256"
    checksum_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="ascii")
    build_info_path = output_dir / f"{artifact_path.name}.build-info.json"
    build_info = {
        **metadata,
        "built_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "sha256": digest,
    }
    build_info_path.write_text(json.dumps(build_info, indent=2) + "\n", encoding="utf-8")
    return artifact_path, checksum_path, build_info_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-dir", type=Path, required=True, help="Next standalone output directory")
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--web-static-dir", type=Path, default=None, help="Directory containing frontend static assets")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    artifact, checksum, build_info = package(
        args.frontend_dir,
        args.version,
        args.commit_sha,
        args.output_dir,
        args.web_static_dir,
    )
    print(f"Created {artifact}")
    print(f"Created {checksum}")
    print(f"Created {build_info}")


if __name__ == "__main__":
    main()
