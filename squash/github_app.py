"""squash/github_app.py — squash GitHub App (Track D / D1).

A GitHub App that auto-attests pull requests and pushes when the changed
file set touches model artifacts (weights, configs, training data, model
cards). The App registers as a Check Run on every relevant commit, posts
``squash attest`` results back to GitHub as a pass / fail / pending check,
and surfaces structured detail (compliance score, policy verdicts,
violation list) in the check-run output panel.

Architecture
------------
* :class:`GitHubAppConfig` — App ID, private key, webhook secret, file
  patterns, base URL.  Round-trips through
  :func:`load_config` / :func:`dump_config_template` (YAML).
* :class:`GitHubAppAuth` — JWT generation (RS256) plus installation
  access-token exchange.  Tokens are cached per installation until
  ``expires_at - 60 s``.
* :class:`GitHubAppClient` — thin urllib wrapper around the GitHub REST
  API: ``check-runs``, ``pulls/<n>/files``, ``commits/<sha>``.
* :class:`WebhookVerifier` — constant-time HMAC-SHA256 verification of
  the ``X-Hub-Signature-256`` header.
* :class:`ModelFileMatcher` — pattern-based decision on whether a list of
  changed files contains model artifacts.
* :class:`AttestationRunner` — given a checked-out working directory,
  runs :class:`squash.attest.AttestPipeline` and renders a check-run
  output payload.
* :class:`WebhookHandler` — dispatches ``pull_request`` and ``push``
  payloads through the runner and posts check runs back to GitHub.
* :func:`serve` — stdlib ``http.server`` based webhook receiver.

The App speaks only the REST API; PyGitHub is optional and never
imported at module load time.  All HTTP is via stdlib ``urllib``.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import fnmatch
import hashlib
import hmac
import http.server
import json
import logging
import os
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

log = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://api.github.com"
USER_AGENT = "squash-github-app/1.0"
SIGNATURE_HEADER = "X-Hub-Signature-256"
EVENT_HEADER = "X-GitHub-Event"
DELIVERY_HEADER = "X-GitHub-Delivery"

DEFAULT_MODEL_PATTERNS: tuple[str, ...] = (
    "*.safetensors",
    "*.gguf",
    "*.bin",
    "*.pt",
    "*.pth",
    "*.onnx",
    "*.h5",
    "*.tflite",
    "*.ckpt",
    "*.pkl",
    "*.npz",
    "config.json",
    "tokenizer.json",
    "tokenizer.model",
    "model.safetensors.index.json",
    "pytorch_model.bin.index.json",
    "**/model_card.md",
    "**/MODEL_CARD.md",
    "**/squash-attest.json",
    "**/cyclonedx-mlbom.json",
    "**/data_lineage_certificate.json",
)


# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class GitHubAppConfig:
    app_id: int = 0
    private_key_path: str = ""
    webhook_secret: str = ""
    api_base: str = DEFAULT_API_BASE
    model_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_MODEL_PATTERNS))
    fail_on_violation: bool = True
    policies: list[str] = field(default_factory=lambda: ["enterprise-strict"])
    clone_depth: int = 1
    workdir_root: str = ""
    listen_host: str = "0.0.0.0"
    listen_port: int = 8088
    skip_scan: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GitHubAppConfig":
        kwargs: dict[str, Any] = {}
        fields_by_name = {f.name: f for f in dataclasses.fields(cls)}
        for k, v in data.items():
            if k in fields_by_name:
                kwargs[k] = v
        return cls(**kwargs)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.app_id or int(self.app_id) <= 0:
            errors.append("app_id must be a positive integer")
        if not self.private_key_path:
            errors.append("private_key_path is required")
        elif not Path(self.private_key_path).expanduser().exists():
            errors.append(
                f"private_key_path does not exist: {self.private_key_path}"
            )
        if not self.webhook_secret:
            errors.append("webhook_secret is required")
        if not self.model_patterns:
            errors.append("model_patterns must not be empty")
        return errors

    def private_key_bytes(self) -> bytes:
        return Path(self.private_key_path).expanduser().read_bytes()


_CONFIG_TEMPLATE = """\
# squash GitHub App config — see `squash github-app config --init` for help.
app_id: 0                           # GitHub App numeric ID
private_key_path: ./squash-app.private-key.pem
webhook_secret: change-me           # `Secret` field on the App settings page
api_base: {api_base}
listen_host: 0.0.0.0
listen_port: 8088
fail_on_violation: true
skip_scan: false
clone_depth: 1
workdir_root: ""                    # blank = system tempdir per delivery
policies:
  - enterprise-strict
model_patterns:
{patterns}
""".format(
    api_base=DEFAULT_API_BASE,
    patterns="\n".join(f"  - {p!r}" for p in DEFAULT_MODEL_PATTERNS),
)


def dump_config_template(out: str | os.PathLike[str]) -> Path:
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_CONFIG_TEMPLATE)
    return p


def load_config(path: str | os.PathLike[str]) -> GitHubAppConfig:
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"GitHub App config not found: {p}")
    text = p.read_text()
    suffix = p.suffix.lower()
    data: Any
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to read YAML config — `pip install pyyaml`"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"GitHub App config must be a mapping: {p}")
    return GitHubAppConfig.from_dict(data)


# ──────────────────────────────────────────────────────────────────────────────
# Webhook signature verification
# ──────────────────────────────────────────────────────────────────────────────


class WebhookVerifier:
    """Verify ``X-Hub-Signature-256`` HMACs from GitHub webhook deliveries."""

    def __init__(self, secret: str) -> None:
        if not secret:
            raise ValueError("webhook secret must be a non-empty string")
        self._secret = secret.encode()

    def expected_signature(self, body: bytes) -> str:
        digest = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def verify(self, body: bytes, header_value: str | None) -> bool:
        if not header_value or not header_value.startswith("sha256="):
            return False
        expected = self.expected_signature(body)
        return hmac.compare_digest(expected, header_value)


# ──────────────────────────────────────────────────────────────────────────────
# JWT (RS256) — stdlib + cryptography
# ──────────────────────────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(app_id: int, private_key_pem: bytes, *, now: int | None = None) -> str:
    """Mint a GitHub App JWT (RS256, ≤10-minute lifetime)."""

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for GitHub App JWT signing"
        ) from exc

    iat = int(now if now is not None else time.time()) - 60
    exp = iat + 9 * 60
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": iat, "exp": exp, "iss": int(app_id)}

    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    ).encode()

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("GitHub App private key must be an RSA key")
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode() + "." + _b64url(sig)


# ──────────────────────────────────────────────────────────────────────────────
# Auth — JWT + installation token exchange
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class _CachedToken:
    token: str
    expires_at: float

    def fresh(self, *, leeway_s: float = 60.0) -> bool:
        return time.time() + leeway_s < self.expires_at


class GitHubAppAuth:
    """Mint App JWTs and exchange them for installation access tokens."""

    def __init__(
        self,
        config: GitHubAppConfig,
        *,
        http_call: Callable[..., dict[str, Any]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._http = http_call
        self._clock = clock or time.time
        self._cache: dict[int, _CachedToken] = {}
        self._lock = threading.Lock()

    def jwt(self) -> str:
        return make_jwt(
            self._config.app_id,
            self._config.private_key_bytes(),
            now=int(self._clock()),
        )

    def installation_token(self, installation_id: int) -> str:
        with self._lock:
            cached = self._cache.get(installation_id)
            if cached and cached.fresh():
                return cached.token

            url = (
                f"{self._config.api_base}/app/installations/"
                f"{installation_id}/access_tokens"
            )
            headers = {
                "Authorization": f"Bearer {self.jwt()}",
                "Accept": "application/vnd.github+json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            }
            response = (self._http or _http_json)(
                "POST", url, headers=headers, body=None,
            )
            token = str(response.get("token", ""))
            expires_at = response.get("expires_at", "")
            if not token:
                raise RuntimeError(
                    f"GitHub did not return an installation token: {response!r}"
                )
            self._cache[installation_id] = _CachedToken(
                token=token,
                expires_at=_parse_iso_utc(expires_at) if expires_at else (
                    self._clock() + 30 * 60
                ),
            )
            return token

    def invalidate(self, installation_id: int) -> None:
        with self._lock:
            self._cache.pop(installation_id, None)


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────


def _http_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: Any = None,
    timeout_s: float = 15.0,
) -> dict[str, Any]:
    data: bytes | None = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        else:
            data = json.dumps(body).encode()

    req = urllib.request.Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None and "Content-Type" not in (headers or {}):
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            payload = resp.read()
            if not payload:
                return {"_status": resp.status}
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                return {"_status": resp.status, "_raw": payload.decode("utf-8", "replace")}
            if isinstance(obj, list):
                return {"_status": resp.status, "_list": obj}
            return obj  # type: ignore[return-value]
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            err = json.loads(body)
        except Exception:  # noqa: BLE001
            err = {"message": body}
        raise GitHubApiError(exc.code, str(err.get("message", "")), err) from exc


class GitHubApiError(RuntimeError):
    def __init__(self, status: int, message: str, body: Any | None = None) -> None:
        super().__init__(f"GitHub API error {status}: {message}")
        self.status = status
        self.message = message
        self.body = body


def _parse_iso_utc(s: str) -> float:
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:  # noqa: BLE001
        return time.time() + 30 * 60


# ──────────────────────────────────────────────────────────────────────────────
# REST client
# ──────────────────────────────────────────────────────────────────────────────


class GitHubAppClient:
    """REST client over ``urllib`` — installation-token authenticated."""

    def __init__(
        self,
        auth: GitHubAppAuth,
        *,
        api_base: str | None = None,
        http_call: Callable[..., dict[str, Any]] | None = None,
    ) -> None:
        self._auth = auth
        self._api_base = (api_base or auth._config.api_base).rstrip("/")
        self._http = http_call or _http_json

    # ── Public API ─────────────────────────────────────────────────────────
    def create_check_run(
        self,
        *,
        installation_id: int,
        owner: str,
        repo: str,
        head_sha: str,
        name: str = "squash / attestation",
        status: str = "in_progress",
        output: dict[str, Any] | None = None,
        details_url: str | None = None,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"name": name, "head_sha": head_sha, "status": status}
        if output is not None:
            body["output"] = output
        if details_url:
            body["details_url"] = details_url
        if external_id:
            body["external_id"] = external_id
        return self._call(
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            installation_id=installation_id,
            body=body,
        )

    def update_check_run(
        self,
        *,
        installation_id: int,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str | None = None,
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
        completed_at: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if conclusion is not None:
            body["conclusion"] = conclusion
        if output is not None:
            body["output"] = output
        if completed_at is not None:
            body["completed_at"] = completed_at
        return self._call(
            "PATCH",
            f"/repos/{owner}/{repo}/check-runs/{check_run_id}",
            installation_id=installation_id,
            body=body,
        )

    def list_pull_request_files(
        self,
        *,
        installation_id: int,
        owner: str,
        repo: str,
        number: int,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            qs = urllib.parse.urlencode({"per_page": per_page, "page": page})
            payload = self._call(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{number}/files?{qs}",
                installation_id=installation_id,
                body=None,
            )
            chunk = payload.get("_list") if "_list" in payload else (
                payload if isinstance(payload, list) else []
            )
            chunk = chunk or []
            out.extend(chunk)
            if len(chunk) < per_page:
                break
            page += 1
        return out

    def get_commit(
        self,
        *,
        installation_id: int,
        owner: str,
        repo: str,
        sha: str,
    ) -> dict[str, Any]:
        return self._call(
            "GET",
            f"/repos/{owner}/{repo}/commits/{sha}",
            installation_id=installation_id,
            body=None,
        )

    # ── Internal ───────────────────────────────────────────────────────────
    def _call(
        self,
        method: str,
        path: str,
        *,
        installation_id: int,
        body: Any,
    ) -> dict[str, Any]:
        token = self._auth.installation_token(installation_id)
        url = path if path.startswith("http") else f"{self._api_base}{path}"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        return self._http(method, url, headers=headers, body=body)


# ──────────────────────────────────────────────────────────────────────────────
# File matching
# ──────────────────────────────────────────────────────────────────────────────


class ModelFileMatcher:
    """Decide whether a list of paths contains model artefacts."""

    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        self._patterns = tuple(patterns) if patterns else DEFAULT_MODEL_PATTERNS

    @property
    def patterns(self) -> tuple[str, ...]:
        return self._patterns

    def matches(self, path: str) -> bool:
        # Normalise leading "./" and Windows separators.
        norm = path.replace("\\", "/").lstrip("./")
        leaf = norm.rsplit("/", 1)[-1]
        for pat in self._patterns:
            pat_norm = pat.lstrip("./")
            if fnmatch.fnmatch(norm, pat_norm):
                return True
            if "/" not in pat_norm and fnmatch.fnmatch(leaf, pat_norm):
                return True
        return False

    def changed_model_files(self, paths: Iterable[str]) -> list[str]:
        return [p for p in paths if self.matches(p)]


# ──────────────────────────────────────────────────────────────────────────────
# Attestation runner
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class AttestationOutcome:
    passed: bool
    model_id: str
    summary: str
    detail_md: str
    violations: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    @property
    def conclusion(self) -> str:
        return "success" if self.passed else "failure"

    def to_check_run_output(self) -> dict[str, Any]:
        title = (
            f"squash attestation passed — {self.model_id}"
            if self.passed
            else f"squash attestation FAILED — {self.model_id}"
        )
        return {
            "title": title,
            "summary": self.summary,
            "text": self.detail_md,
        }


class AttestationRunner:
    """Run :class:`squash.attest.AttestPipeline` and render a check-run output."""

    def __init__(
        self,
        config: GitHubAppConfig,
        *,
        attest_callable: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._attest = attest_callable

    def run(
        self,
        workdir: str | os.PathLike[str],
        changed_model_files: list[str],
        *,
        model_id: str = "",
    ) -> AttestationOutcome:
        wd = Path(workdir)
        if not wd.exists():
            return AttestationOutcome(
                passed=False,
                model_id=model_id or wd.name,
                summary="Working directory does not exist",
                detail_md=f"```\nworkdir not found: {wd}\n```\n",
                violations=["workdir_missing"],
            )

        if not changed_model_files:
            return AttestationOutcome(
                passed=True,
                model_id=model_id or wd.name,
                summary="No model files changed — nothing to attest.",
                detail_md=(
                    "_No paths in this commit matched the configured "
                    "`model_patterns`._\n"
                ),
            )

        # Resolve a model directory that exists in the workdir.
        model_paths = [wd / Path(f) for f in changed_model_files]
        existing = [p for p in model_paths if p.exists()]
        if existing:
            target = existing[0].parent if existing[0].is_file() else existing[0]
        else:
            target = wd

        try:
            from squash.attest import (
                AttestConfig,
                AttestPipeline,
                AttestationViolationError,
            )
        except Exception as exc:  # noqa: BLE001
            return AttestationOutcome(
                passed=False,
                model_id=model_id or target.name,
                summary="squash attest module unavailable",
                detail_md=f"```\n{exc}\n```\n",
                violations=["attest_import"],
            )

        cfg = AttestConfig(
            model_path=target,
            output_dir=wd / ".squash" / "out",
            model_id=model_id or target.name,
            policies=list(self._config.policies),
            sign=False,
            offline=True,
            fail_on_violation=False,
            skip_scan=bool(self._config.skip_scan),
        )

        attest_call = self._attest or AttestPipeline.run
        try:
            result = attest_call(cfg)
        except AttestationViolationError as exc:
            return AttestationOutcome(
                passed=False,
                model_id=cfg.model_id,
                summary="Attestation raised AttestationViolationError",
                detail_md=f"```\n{exc}\n```\n",
                violations=["violation_error"],
            )
        except FileNotFoundError as exc:
            return AttestationOutcome(
                passed=False,
                model_id=cfg.model_id,
                summary="Model path missing in clone",
                detail_md=f"```\n{exc}\n```\n",
                violations=["model_missing"],
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("AttestPipeline crashed")
            return AttestationOutcome(
                passed=False,
                model_id=cfg.model_id,
                summary=f"AttestPipeline raised {type(exc).__name__}",
                detail_md=f"```\n{exc}\n```\n",
                violations=[type(exc).__name__],
            )

        return _outcome_from_attest_result(result, changed_model_files)


def _outcome_from_attest_result(
    result: Any, changed_model_files: list[str]
) -> AttestationOutcome:
    passed = bool(getattr(result, "passed", False))
    model_id = str(getattr(result, "model_id", "") or "model")
    policy_results = getattr(result, "policy_results", {}) or {}

    lines = [
        "### squash attestation",
        "",
        f"**Model:** `{model_id}`",
        f"**Status:** {'PASS' if passed else 'FAIL'}",
        "",
        "**Changed model files:**",
    ]
    for f in changed_model_files[:25]:
        lines.append(f"- `{f}`")
    if len(changed_model_files) > 25:
        lines.append(f"- … and {len(changed_model_files) - 25} more")
    lines.append("")

    violations: list[str] = []
    if policy_results:
        lines.append("**Policy results:**")
        lines.append("")
        lines.append("| Policy | Status | Details |")
        lines.append("| --- | --- | --- |")
        for name, pr in policy_results.items():
            pr_passed = bool(getattr(pr, "passed", False))
            details = ""
            failed = getattr(pr, "failed_rules", None) or getattr(pr, "violations", None)
            if isinstance(failed, list) and failed:
                details = ", ".join(str(x) for x in failed[:5])
                violations.extend(str(x) for x in failed)
            elif hasattr(pr, "summary") and callable(pr.summary):
                details = pr.summary()
            else:
                details = "(no details)"
            lines.append(
                f"| `{name}` | {'PASS' if pr_passed else 'FAIL'} | {details} |"
            )
        lines.append("")

    scan_result = getattr(result, "scan_result", None)
    if scan_result is not None:
        scan_status = getattr(scan_result, "status", "unknown")
        lines.append(f"**Security scan:** `{scan_status}`")
        lines.append("")
        if str(scan_status).lower() == "unsafe":
            violations.append("scan:unsafe")

    err = getattr(result, "error", "")
    if err:
        lines.append(f"**Error:** {err}")
        violations.append(str(err))

    artifacts = []
    for attr in (
        "cyclonedx_path", "spdx_json_path", "spdx_tv_path",
        "signature_path", "master_record_path", "vex_report_path",
    ):
        v = getattr(result, attr, None)
        if v:
            artifacts.append(str(v))

    summary = (
        f"squash attestation passed for {model_id}"
        if passed
        else f"squash attestation failed for {model_id} — "
             f"{len(violations) or 1} issue(s)"
    )

    return AttestationOutcome(
        passed=passed,
        model_id=model_id,
        summary=summary,
        detail_md="\n".join(lines) + "\n",
        violations=violations,
        artifacts=artifacts,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Workspace materialisation
# ──────────────────────────────────────────────────────────────────────────────


def clone_repo_at_sha(
    *,
    clone_url: str,
    sha: str,
    destination: str | os.PathLike[str],
    depth: int = 1,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> Path:
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    run = runner or subprocess.run

    init = run(
        ["git", "init", "--quiet", str(dest)],
        capture_output=True, text=True, check=False,
    )
    if init.returncode != 0:
        raise RuntimeError(f"git init failed: {init.stderr}")

    fetch_args = ["git", "-C", str(dest), "fetch", "--depth", str(max(depth, 1)),
                  clone_url, sha]
    fetch = run(fetch_args, capture_output=True, text=True, check=False)
    if fetch.returncode != 0:
        raise RuntimeError(f"git fetch failed: {fetch.stderr}")

    checkout = run(
        ["git", "-C", str(dest), "checkout", "--detach", sha],
        capture_output=True, text=True, check=False,
    )
    if checkout.returncode != 0:
        raise RuntimeError(f"git checkout failed: {checkout.stderr}")
    return dest


# ──────────────────────────────────────────────────────────────────────────────
# Webhook handler
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class WebhookOutcome:
    handled: bool
    event: str
    delivery_id: str = ""
    repo: str = ""
    head_sha: str = ""
    check_run_id: int | None = None
    conclusion: str = ""
    detail: str = ""
    skipped_reason: str = ""


class WebhookHandler:
    """Dispatch webhook events to the attestation runner and post check runs."""

    def __init__(
        self,
        config: GitHubAppConfig,
        *,
        client: GitHubAppClient | None = None,
        runner: AttestationRunner | None = None,
        cloner: Callable[..., Path] | None = None,
    ) -> None:
        self._config = config
        self._matcher = ModelFileMatcher(config.model_patterns)
        if client is not None:
            self._auth = client._auth  # type: ignore[attr-defined]
            self._client = client
        else:
            self._auth = GitHubAppAuth(config)
            self._client = GitHubAppClient(self._auth)
        self._runner = runner or AttestationRunner(config)
        self._cloner = cloner or clone_repo_at_sha

    # ── Entry point ────────────────────────────────────────────────────────

    def handle(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        delivery_id: str = "",
    ) -> WebhookOutcome:
        if event == "ping":
            return WebhookOutcome(
                handled=True, event=event, delivery_id=delivery_id,
                detail="ping acknowledged",
            )
        if event == "pull_request":
            return self._handle_pull_request(payload, delivery_id=delivery_id)
        if event == "push":
            return self._handle_push(payload, delivery_id=delivery_id)
        if event == "check_run":
            return WebhookOutcome(
                handled=True, event=event, delivery_id=delivery_id,
                detail="check_run echo ignored",
                skipped_reason="event:check_run",
            )
        return WebhookOutcome(
            handled=False, event=event, delivery_id=delivery_id,
            skipped_reason=f"unsupported_event:{event}",
        )

    # ── pull_request ───────────────────────────────────────────────────────

    def _handle_pull_request(
        self, payload: Mapping[str, Any], *, delivery_id: str
    ) -> WebhookOutcome:
        action = str(payload.get("action", ""))
        if action not in {"opened", "synchronize", "reopened", "ready_for_review"}:
            return WebhookOutcome(
                handled=True, event="pull_request", delivery_id=delivery_id,
                skipped_reason=f"action:{action}",
            )

        pr = payload.get("pull_request") or {}
        repo_obj = payload.get("repository") or {}
        installation_id = int(((payload.get("installation") or {}).get("id")) or 0)
        owner = str(((repo_obj.get("owner") or {}).get("login")) or "")
        repo = str(repo_obj.get("name") or "")
        head = pr.get("head") or {}
        head_sha = str(head.get("sha") or "")
        clone_url = str(repo_obj.get("clone_url") or "")
        number = int(pr.get("number") or 0)
        repo_full = f"{owner}/{repo}"

        if not (installation_id and owner and repo and head_sha and number):
            return WebhookOutcome(
                handled=False, event="pull_request", delivery_id=delivery_id,
                repo=repo_full, head_sha=head_sha,
                skipped_reason="missing_required_fields",
            )

        files = self._client.list_pull_request_files(
            installation_id=installation_id, owner=owner, repo=repo, number=number,
        )
        changed_paths = [str(f.get("filename", "")) for f in files if f.get("filename")]
        model_files = self._matcher.changed_model_files(changed_paths)

        return self._run_and_post(
            installation_id=installation_id,
            owner=owner, repo=repo, head_sha=head_sha,
            clone_url=clone_url,
            changed_model_files=model_files,
            delivery_id=delivery_id,
            event="pull_request",
        )

    # ── push ───────────────────────────────────────────────────────────────

    def _handle_push(
        self, payload: Mapping[str, Any], *, delivery_id: str
    ) -> WebhookOutcome:
        if payload.get("deleted"):
            return WebhookOutcome(
                handled=True, event="push", delivery_id=delivery_id,
                skipped_reason="branch_deleted",
            )
        repo_obj = payload.get("repository") or {}
        installation_id = int(((payload.get("installation") or {}).get("id")) or 0)
        owner = str(((repo_obj.get("owner") or {}).get("login")) or
                    (repo_obj.get("owner") or {}).get("name") or "")
        repo = str(repo_obj.get("name") or "")
        head_sha = str(payload.get("after") or payload.get("head_commit", {}).get("id") or "")
        clone_url = str(repo_obj.get("clone_url") or "")
        repo_full = f"{owner}/{repo}"

        if not (installation_id and owner and repo and head_sha):
            return WebhookOutcome(
                handled=False, event="push", delivery_id=delivery_id,
                repo=repo_full, head_sha=head_sha,
                skipped_reason="missing_required_fields",
            )

        # Aggregate changed file paths across all commits in the push payload.
        changed: set[str] = set()
        for commit in payload.get("commits") or []:
            for key in ("added", "modified", "removed"):
                for p in commit.get(key) or []:
                    changed.add(str(p))
        head_commit = payload.get("head_commit") or {}
        for key in ("added", "modified", "removed"):
            for p in head_commit.get(key) or []:
                changed.add(str(p))
        model_files = self._matcher.changed_model_files(sorted(changed))

        return self._run_and_post(
            installation_id=installation_id,
            owner=owner, repo=repo, head_sha=head_sha,
            clone_url=clone_url,
            changed_model_files=model_files,
            delivery_id=delivery_id,
            event="push",
        )

    # ── shared post-processing ─────────────────────────────────────────────

    def _run_and_post(
        self,
        *,
        installation_id: int,
        owner: str,
        repo: str,
        head_sha: str,
        clone_url: str,
        changed_model_files: list[str],
        delivery_id: str,
        event: str,
    ) -> WebhookOutcome:
        repo_full = f"{owner}/{repo}"

        if not changed_model_files:
            outcome = AttestationOutcome(
                passed=True,
                model_id=repo_full,
                summary="No model files changed — squash check skipped.",
                detail_md=(
                    "_No paths in this commit matched the configured "
                    "`model_patterns`._\n"
                ),
            )
            check = self._client.create_check_run(
                installation_id=installation_id, owner=owner, repo=repo,
                head_sha=head_sha, status="completed",
                output=outcome.to_check_run_output(),
                external_id=delivery_id or None,
            )
            check.update({"_status": check.get("_status", 201)})
            return WebhookOutcome(
                handled=True, event=event, delivery_id=delivery_id,
                repo=repo_full, head_sha=head_sha,
                check_run_id=int(check.get("id") or 0) or None,
                conclusion="neutral",
                detail="no model files in changeset",
                skipped_reason="no_model_files",
            )

        # Pending check_run.
        pending = self._client.create_check_run(
            installation_id=installation_id, owner=owner, repo=repo,
            head_sha=head_sha, status="in_progress",
            output={
                "title": "squash attestation in progress",
                "summary": (
                    f"Attesting {len(changed_model_files)} changed model "
                    f"file(s) on `{head_sha[:7]}`."
                ),
            },
            external_id=delivery_id or None,
        )
        check_run_id = int(pending.get("id") or 0)

        # Materialise workspace.
        workdir_root = (
            Path(self._config.workdir_root).expanduser()
            if self._config.workdir_root
            else None
        )
        if workdir_root is not None:
            workdir_root.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(
            prefix=f"squash-app-{head_sha[:7]}-",
            dir=str(workdir_root) if workdir_root else None,
        )
        try:
            wd = Path(tmp.name) / "repo"
            try:
                self._cloner(
                    clone_url=clone_url, sha=head_sha,
                    destination=wd, depth=self._config.clone_depth,
                )
            except Exception as exc:  # noqa: BLE001
                outcome = AttestationOutcome(
                    passed=False,
                    model_id=repo_full,
                    summary=f"Clone failed: {exc}",
                    detail_md=f"```\n{exc}\n```\n",
                    violations=["clone_failed"],
                )
            else:
                outcome = self._runner.run(
                    workdir=wd,
                    changed_model_files=changed_model_files,
                    model_id=repo_full,
                )
        finally:
            try:
                tmp.cleanup()
            except Exception:  # noqa: BLE001
                pass

        if check_run_id:
            self._client.update_check_run(
                installation_id=installation_id, owner=owner, repo=repo,
                check_run_id=check_run_id,
                status="completed",
                conclusion=outcome.conclusion,
                output=outcome.to_check_run_output(),
                completed_at=_now_iso(),
            )

        return WebhookOutcome(
            handled=True, event=event, delivery_id=delivery_id,
            repo=repo_full, head_sha=head_sha,
            check_run_id=check_run_id or None,
            conclusion=outcome.conclusion,
            detail=outcome.summary,
        )


# ──────────────────────────────────────────────────────────────────────────────
# HTTP server
# ──────────────────────────────────────────────────────────────────────────────


class _WebhookHTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "squash-github-app/1.0"
    handler: WebhookHandler  # populated by serve()
    verifier: WebhookVerifier  # populated by serve()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        log.info("webhook %s — %s", self.address_string(), format % args)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/healthz", "/health"):
            return self._send_json(200, {"ok": True, "service": "squash-github-app"})
        return self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/webhook", "/"):
            return self._send_json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        sig = self.headers.get(SIGNATURE_HEADER) or self.headers.get(
            SIGNATURE_HEADER.lower()
        )
        if not self.verifier.verify(body, sig):
            return self._send_json(401, {"error": "invalid signature"})

        event = self.headers.get(EVENT_HEADER) or "unknown"
        delivery = self.headers.get(DELIVERY_HEADER) or ""

        try:
            payload = json.loads(body or b"{}") if body else {}
        except json.JSONDecodeError as exc:
            return self._send_json(400, {"error": f"invalid json: {exc}"})

        try:
            outcome = self.handler.handle(event, payload, delivery_id=delivery)
        except GitHubApiError as exc:
            log.exception("GitHub API error in webhook")
            return self._send_json(502, {"error": str(exc), "status": exc.status})
        except Exception as exc:  # noqa: BLE001
            log.exception("webhook handler crashed")
            return self._send_json(500, {"error": str(exc)})

        return self._send_json(200, dataclasses.asdict(outcome))

    def _send_json(self, status: int, body: Mapping[str, Any]) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(
    config: GitHubAppConfig,
    *,
    handler: WebhookHandler | None = None,
    host: str | None = None,
    port: int | None = None,
    server_factory: Callable[..., http.server.HTTPServer] | None = None,
) -> http.server.HTTPServer:
    """Start a threading HTTP server that receives GitHub webhook deliveries.

    Returns the server instance.  Caller is responsible for invoking
    ``serve_forever()`` (or shutting it down).
    """

    errors = config.validate()
    if errors:
        raise ValueError("invalid GitHubAppConfig: " + "; ".join(errors))

    h = handler or WebhookHandler(config)
    verifier = WebhookVerifier(config.webhook_secret)

    cls = type(
        "_BoundWebhookHandler",
        (_WebhookHTTPHandler,),
        {"handler": h, "verifier": verifier},
    )
    factory = server_factory or _ThreadingHTTPServer
    bind_host = host if host is not None else config.listen_host
    bind_port = int(port if port is not None else config.listen_port)
    server = factory((bind_host, bind_port), cls)
    log.info("squash-github-app listening on %s:%d", bind_host, bind_port)
    return server


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


__all__ = [
    "DEFAULT_API_BASE",
    "DEFAULT_MODEL_PATTERNS",
    "AttestationOutcome",
    "AttestationRunner",
    "GitHubAppAuth",
    "GitHubAppClient",
    "GitHubAppConfig",
    "GitHubApiError",
    "ModelFileMatcher",
    "WebhookHandler",
    "WebhookOutcome",
    "WebhookVerifier",
    "clone_repo_at_sha",
    "dump_config_template",
    "load_config",
    "make_jwt",
    "serve",
]
