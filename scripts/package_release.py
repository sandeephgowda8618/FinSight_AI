#!/usr/bin/env python3
"""Build a versioned FinSight application bundle from locked/build outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z")
SHA_PATTERN = re.compile(r"\A[0-9a-f]{40}\Z")


def package(frontend_dir: Path, version: str, commit_sha: str | None, output_dir: Path) -> tuple[Path, Path, Path]:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("version must be a numeric semantic version, optionally with a prerelease/build suffix")
    if commit_sha and not SHA_PATTERN.fullmatch(commit_sha):
        raise ValueError("commit SHA must be a full 40-character lowercase hexadecimal SHA")
    if not frontend_dir.is_dir() or not (frontend_dir / "server.js").is_file():
        raise FileNotFoundError("frontend standalone build is missing server.js")

    web_static = ROOT / "apps/web/.next/static"
    runtime_config = ROOT / "apps/web/app/api/runtime-config/route.js"
    if not web_static.is_dir() or not runtime_config.is_file():
        raise FileNotFoundError("build the frontend before packaging")

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_base = f"finsight-{version}" + (f"-{commit_sha[:12]}" if commit_sha else "")
    with tempfile.TemporaryDirectory(prefix="finsight-release-") as temp_dir:
        payload = Path(temp_dir) / "finsight"
        frontend = payload / "frontend"
        shutil.copytree(frontend_dir, frontend, symlinks=True)
        shutil.copytree(web_static, frontend / ".next/static", symlinks=True)

        backend = payload / "backend"
        shutil.copytree(ROOT / "apps/api/app", backend / "app", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(ROOT / "apps/api/migrations", backend / "migrations")
        shutil.copy2(ROOT / "apps/api/requirements.lock", backend / "requirements.lock")

        metadata = {
            "artifact": artifact_base,
            "version": version,
            "commit_sha": commit_sha,
            "frontend": {"runtime": "Node.js 22", "entrypoint": "node frontend/server.js"},
            "backend": {"runtime": "Python 3.12", "entrypoint": "python -m uvicorn app.main:app"},
            "database_migrations": ["0001_auth_identity.sql", "0002_platform_authorization.sql", "0003_auth_audit_and_login_throttling.sql", "0004_immutable_auth_audit.sql", "0005_mfa_factors.sql", "0006_mfa_login_challenges.sql"],
            "configuration": "Runtime values are supplied through environment variables; see RELEASE_README.md.",
        }
        (payload / "RELEASE-METADATA.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        release_readme = ROOT / "docs/release/RELEASE_README.md"
        shutil.copy2(release_readme, payload / "RELEASE_README.md")

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
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    artifact, checksum, build_info = package(args.frontend_dir, args.version, args.commit_sha, args.output_dir)
    print(f"Created {artifact}")
    print(f"Created {checksum}")
    print(f"Created {build_info}")


if __name__ == "__main__":
    main()
