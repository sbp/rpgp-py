from __future__ import annotations

import argparse
import gc
import importlib.metadata
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SECRET_KEY_FIXTURE = FIXTURES / "cleartext-key-01.asc"
DEFAULT_OUTPUT = ROOT / "docs" / "benchmarks" / "results.json"
PASSWORD = "hunter2"
DEFAULT_PYTHON = "3.12"


@dataclass(frozen=True, slots=True)
class BenchmarkSpec:
    """Description of one reproducible benchmark."""

    slug: str
    label: str
    iterations: int


@dataclass(frozen=True, slots=True)
class BackendSpec:
    """How to invoke one backend in an isolated `uv run` environment."""

    name: str
    extra_args: tuple[str, ...] = ()


BENCHMARK_SPECS: tuple[BenchmarkSpec, ...] = (
    BenchmarkSpec("parse_public_key", "Parse armored public key", 200),
    BenchmarkSpec("parse_secret_key", "Parse armored secret key", 120),
    BenchmarkSpec("detached_sign_verify", "Detached sign + verify", 16),
    BenchmarkSpec(
        "recipient_encrypt_decrypt",
        "Encrypt + decrypt to recipient",
        10,
    ),
    BenchmarkSpec(
        "password_encrypt_decrypt",
        "Encrypt + decrypt with password",
        16,
    ),
)

BACKENDS: tuple[BackendSpec, ...] = (
    BackendSpec("rpgp-py"),
    BackendSpec("PGPy13"),
    BackendSpec("PGPy"),
)


class BenchmarkRunner:
    """Small helper that runs named callables with warmups and repeated samples."""

    def __init__(self) -> None:
        self._benchmarks: dict[str, Callable[[], None]] = {}

    def add(self, name: str, callback: Callable[[], None]) -> None:
        self._benchmarks[name] = callback

    def run(self, *, repeat: int) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for spec in BENCHMARK_SPECS:
            callback = self._benchmarks[spec.slug]
            callback()
            samples_ms = _measure_callback(
                callback,
                iterations=spec.iterations,
                repeat=repeat,
            )
            results[spec.slug] = {
                "label": spec.label,
                "iterations": spec.iterations,
                "samples_ms": samples_ms,
                "median_ms": round(statistics.median(samples_ms), 3),
                "min_ms": round(min(samples_ms), 3),
                "max_ms": round(max(samples_ms), 3),
            }
        return results


def _fixture_text() -> str:
    return SECRET_KEY_FIXTURE.read_text(encoding="utf-8")


def _build_payload(size: int) -> bytes:
    seed = b"rpgp-py-benchmark-payload-"
    repeats = max(1, (size // len(seed)) + 1)
    return (seed * repeats)[:size]


def _measure_callback(
    callback: Callable[[], None],
    *,
    iterations: int,
    repeat: int,
) -> list[float]:
    samples_ms: list[float] = []
    gc_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(repeat):
            start = time.perf_counter_ns()
            for _ in range(iterations):
                callback()
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            samples_ms.append(round(elapsed_ms / iterations, 3))
    finally:
        if gc_enabled:
            gc.enable()
    return samples_ms


def _version_or_fallback(distribution_name: str, *, fallback: str) -> str:
    try:
        return importlib.metadata.version(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        return fallback


def _build_release_wheel(*, python_version: str) -> Path:
    dist_dir = ROOT / "dist" / "benchmark"
    dist_dir.mkdir(parents=True, exist_ok=True)
    for wheel in dist_dir.glob("*.whl"):
        wheel.unlink()

    command = [
        "uv",
        "build",
        "--python",
        python_version,
        "--wheel",
        "--out-dir",
        str(dist_dir),
    ]
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )

    wheels = sorted(dist_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"Expected exactly one benchmark wheel, found {len(wheels)}")
    return wheels[0]


def _run_rpgp_backend(payload: bytes, *, repeat: int) -> dict[str, Any]:
    from openpgp import (
        DetachedSignature,
        Message,
        PublicKey,
        SecretKey,
        encrypt_message_to_recipient,
        encrypt_message_with_password,
    )

    secret_key_armor = _fixture_text()
    secret_key, _ = SecretKey.from_armor(secret_key_armor)
    public_key = secret_key.to_public_key()
    public_key_armor = public_key.to_armored()

    runner = BenchmarkRunner()

    def parse_public_key() -> None:
        reparsed, _ = PublicKey.from_armor(public_key_armor)
        if reparsed.fingerprint != public_key.fingerprint:
            raise RuntimeError("public-key parse benchmark returned a different key")

    def parse_secret_key() -> None:
        reparsed, _ = SecretKey.from_armor(secret_key_armor)
        if reparsed.fingerprint != secret_key.fingerprint:
            raise RuntimeError("secret-key parse benchmark returned a different key")

    def detached_sign_verify() -> None:
        signature = DetachedSignature.sign_binary(payload, secret_key)
        signature.verify(public_key, payload)

    def recipient_encrypt_decrypt() -> None:
        armored = encrypt_message_to_recipient(payload, public_key)
        message, _ = Message.from_armor(armored)
        decrypted = message.decrypt(secret_key)
        if decrypted.payload_bytes() != payload:
            raise RuntimeError(
                "recipient decrypt benchmark returned a different payload"
            )

    def password_encrypt_decrypt() -> None:
        armored = encrypt_message_with_password(payload, PASSWORD)
        message, _ = Message.from_armor(armored)
        decrypted = message.decrypt_with_password(PASSWORD)
        if decrypted.payload_bytes() != payload:
            raise RuntimeError(
                "password decrypt benchmark returned a different payload"
            )

    runner.add("parse_public_key", parse_public_key)
    runner.add("parse_secret_key", parse_secret_key)
    runner.add("detached_sign_verify", detached_sign_verify)
    runner.add("recipient_encrypt_decrypt", recipient_encrypt_decrypt)
    runner.add("password_encrypt_decrypt", password_encrypt_decrypt)

    return {
        "backend": "rpgp-py",
        "package_version": _version_or_fallback("rpgp-py", fallback="local"),
        "implementation": "rpgp / pgp Rust core through PyO3 abi3 bindings",
        "results": runner.run(repeat=repeat),
    }


def _run_pgpy_backend(
    payload: bytes,
    *,
    repeat: int,
    distribution_name: str,
) -> dict[str, Any]:
    warnings.simplefilter("ignore")
    import pgpy  # type: ignore[import-not-found]

    secret_key_armor = _fixture_text()
    secret_key, _ = pgpy.PGPKey.from_blob(secret_key_armor)
    public_key = secret_key.pubkey
    public_key_armor = str(public_key)
    payload_text = payload.decode("utf-8")

    runner = BenchmarkRunner()

    def parse_public_key() -> None:
        reparsed, _ = pgpy.PGPKey.from_blob(public_key_armor)
        if str(reparsed.fingerprint) != str(public_key.fingerprint):
            raise RuntimeError("public-key parse benchmark returned a different key")

    def parse_secret_key() -> None:
        reparsed, _ = pgpy.PGPKey.from_blob(secret_key_armor)
        if str(reparsed.fingerprint) != str(secret_key.fingerprint):
            raise RuntimeError("secret-key parse benchmark returned a different key")

    def detached_sign_verify() -> None:
        signature = secret_key.sign(payload, detached=True)
        verification = public_key.verify(payload, signature)
        if not bool(verification):
            raise RuntimeError("signature verification failed")

    def recipient_encrypt_decrypt() -> None:
        message = pgpy.PGPMessage.new(payload)
        encrypted = public_key.encrypt(message)
        decrypted = secret_key.decrypt(encrypted)
        if decrypted.message != payload_text:
            raise RuntimeError(
                "recipient decrypt benchmark returned a different payload"
            )

    def password_encrypt_decrypt() -> None:
        message = pgpy.PGPMessage.new(payload)
        encrypted = message.encrypt(PASSWORD)
        decrypted = encrypted.decrypt(PASSWORD)
        if decrypted.message != payload_text:
            raise RuntimeError(
                "password decrypt benchmark returned a different payload"
            )

    runner.add("parse_public_key", parse_public_key)
    runner.add("parse_secret_key", parse_secret_key)
    runner.add("detached_sign_verify", detached_sign_verify)
    runner.add("recipient_encrypt_decrypt", recipient_encrypt_decrypt)
    runner.add("password_encrypt_decrypt", password_encrypt_decrypt)

    return {
        "backend": distribution_name,
        "package_version": _version_or_fallback(distribution_name, fallback="unknown"),
        "implementation": "pure-Python PGPy API",
        "results": runner.run(repeat=repeat),
    }


def _run_backend(
    backend_name: str, *, payload_bytes: int, repeat: int
) -> dict[str, Any]:
    payload = _build_payload(payload_bytes)
    if backend_name == "rpgp-py":
        result = _run_rpgp_backend(payload, repeat=repeat)
    elif backend_name in {"PGPy13", "PGPy"}:
        result = _run_pgpy_backend(
            payload,
            repeat=repeat,
            distribution_name=backend_name,
        )
    else:
        raise ValueError(f"Unsupported backend: {backend_name}")

    result["payload_bytes"] = payload_bytes
    result["repeat"] = repeat
    result["python_version"] = platform.python_version()
    result["platform"] = platform.platform()
    return result


def _run_backend_subprocess(
    backend: BackendSpec,
    *,
    python_version: str,
    payload_bytes: int,
    repeat: int,
    rpgp_wheel: Path,
) -> dict[str, Any]:
    package_args: tuple[str, ...]
    if backend.name == "rpgp-py":
        package_args = ("--with", str(rpgp_wheel))
    elif backend.name == "PGPy13":
        package_args = ("--with", "PGPy13")
    elif backend.name == "PGPy":
        package_args = ("--with", "PGPy")
    else:
        raise ValueError(f"Unsupported backend: {backend.name}")

    command = [
        "uv",
        "run",
        "--python",
        python_version,
        "--no-project",
        *package_args,
        "python",
        str(Path(__file__).resolve()),
        "--backend",
        backend.name,
        "--payload-bytes",
        str(payload_bytes),
        "--repeat",
        str(repeat),
        "--json",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    return json.loads(completed.stdout)


def _orchestrate(
    *, python_version: str, payload_bytes: int, repeat: int
) -> dict[str, Any]:
    rpgp_wheel = _build_release_wheel(python_version=python_version)
    backend_results = [
        _run_backend_subprocess(
            backend,
            python_version=python_version,
            payload_bytes=payload_bytes,
            repeat=repeat,
            rpgp_wheel=rpgp_wheel,
        )
        for backend in BACKENDS
    ]
    return {
        "benchmark_python": python_version,
        "payload_bytes": payload_bytes,
        "repeat": repeat,
        "benchmarks": [
            {"slug": spec.slug, "label": spec.label, "iterations": spec.iterations}
            for spec in BENCHMARK_SPECS
        ],
        "backends": backend_results,
        "notes": [
            "PGPy does not import on CPython 3.13 because it still imports stdlib imghdr.",
            "The orchestrator therefore benchmarks every backend on the same CPython 3.12 runtime.",
            "Each median is the per-operation median across repeated timed samples.",
            "The rpgp-py backend is benchmarked from a freshly built release wheel, not an editable dev build.",
        ],
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reproducible rpgp-py vs PGPy benchmark runner."
    )
    parser.add_argument("--backend", choices=[backend.name for backend in BACKENDS])
    parser.add_argument(
        "--python-version",
        default=DEFAULT_PYTHON,
        help=(
            "Python version used by the orchestrator for all backends. "
            f"Defaults to {DEFAULT_PYTHON}."
        ),
    )
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output path for the orchestrated JSON report.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit backend JSON to stdout (used by subprocess runs).",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.backend is not None:
        result = _run_backend(
            args.backend,
            payload_bytes=args.payload_bytes,
            repeat=args.repeat,
        )
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    report = _orchestrate(
        python_version=args.python_version,
        payload_bytes=args.payload_bytes,
        repeat=args.repeat,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        output_display = args.output
        try:
            output_display = args.output.resolve().relative_to(ROOT)
        except ValueError:
            output_display = args.output
        print(f"Wrote benchmark report to {output_display}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
