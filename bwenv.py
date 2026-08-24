#!/usr/bin/env python3
"""Resolve Bitwarden/Vaultwarden secrets from 1Password-compatible references.

The public compatibility contract is ``op://organisation/item/field``. This
tool delegates authentication and vault access to the official ``bw`` CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


OP_URI_PATTERN = re.compile(r"^op://([^/]+)/([^/]+)/(.+)$")
TEMPLATE_REFERENCE_PATTERN = re.compile(
    r"\{\{\s*(op://[^\s{}]+)\s*\}\}|(?<![A-Za-z0-9_])"
    r"(op://[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+/[A-Za-z0-9._~/%-]+)"
)
KEYCHAIN_ACCOUNT = "BW_SESSION"


class BWEnvError(RuntimeError):
    """Base error that is safe to show to an operator."""


class ResolutionError(BWEnvError):
    """A reference cannot be resolved deterministically."""


class OutputExistsError(BWEnvError):
    """Refuse to overwrite an existing injected file without approval."""


class KeychainError(BWEnvError):
    """The macOS Keychain cannot provide the requested session."""


@dataclass(frozen=True)
class OpReference:
    organization: str
    item: str
    field: str

    @property
    def item_uri(self) -> str:
        return f"op://{self.organization}/{self.item}"

    @property
    def uri(self) -> str:
        return f"{self.item_uri}/{self.field}"


class URIParser:
    """Compatibility parser retained for callers that imported the old module."""

    @staticmethod
    def parse_op_uri(uri: str) -> tuple[str, str, str] | None:
        match = OP_URI_PATTERN.fullmatch(uri)
        return match.groups() if match else None

    @staticmethod
    def parse_bw_uri(uri: str) -> str | None:
        if not uri.startswith("bw://"):
            return None
        parts = uri.removeprefix("bw://").split("/")
        return uri if len(parts) >= 3 and all(parts) else None

    @classmethod
    def parse_uri(cls, uri: str) -> tuple[str, str, str] | None:
        return cls.parse_op_uri(uri)

    @classmethod
    def is_op_uri(cls, uri: str) -> bool:
        return cls.parse_op_uri(uri) is not None

    @classmethod
    def is_bw_uri(cls, uri: str) -> bool:
        return cls.parse_bw_uri(uri) is not None

    @classmethod
    def is_supported_uri(cls, uri: str) -> bool:
        return cls.is_op_uri(uri) or cls.is_bw_uri(uri)


def parse_op_reference(uri: str) -> OpReference:
    parsed = URIParser.parse_op_uri(uri)
    if parsed is None:
        raise ResolutionError(f"invalid op:// reference: {uri}")
    return OpReference(*parsed)


def _json_list(output: str, command: str) -> list[dict]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise BWEnvError(f"Bitwarden returned invalid JSON for {command}") from error
    if not isinstance(value, list):
        raise BWEnvError(f"Bitwarden returned an invalid result for {command}")
    return value


def _default_bw_runner(args: list[str], env: Mapping[str, str]) -> str:
    try:
        result = subprocess.run(
            ["bw", *args], check=False, capture_output=True, text=True, env=dict(env)
        )
    except FileNotFoundError as error:
        raise BWEnvError("Bitwarden CLI 'bw' was not found") from error
    if result.returncode != 0:
        raise BWEnvError(f"Bitwarden command failed: {' '.join(args[:2])}")
    return result.stdout


class VaultResolver:
    """Fail-closed resolver using the official Bitwarden CLI JSON output."""

    def __init__(self, *, runner: Callable[[list[str], Mapping[str, str]], str] = _default_bw_runner,
                 session: str | None = None, sync: bool = True):
        self.runner = runner
        self.session = session
        self.sync = sync
        self._prepared = False
        self._organizations: list[dict] | None = None
        self._items: list[dict] | None = None

    def _environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        if self.session:
            environment["BW_SESSION"] = self.session
        return environment

    def _run(self, args: list[str]) -> str:
        try:
            return self.runner(args, self._environment())
        except BWEnvError:
            raise
        except Exception as error:
            raise BWEnvError(f"Bitwarden command failed: {' '.join(args[:2])}") from error

    def _prepare(self) -> None:
        if self._prepared:
            return
        try:
            status = json.loads(self._run(["status"]))
        except json.JSONDecodeError as error:
            raise BWEnvError("Bitwarden returned invalid status JSON") from error
        if not isinstance(status, dict) or status.get("status") != "unlocked":
            raise BWEnvError("Bitwarden vault is not unlocked; refresh the configured session")
        if self.sync:
            self._run(["sync"])
        self._prepared = True

    def _organizations_list(self) -> list[dict]:
        self._prepare()
        if self._organizations is None:
            self._organizations = _json_list(
                self._run(["list", "organizations"]), "list organizations"
            )
        return self._organizations

    def _items_list(self) -> list[dict]:
        self._prepare()
        if self._items is None:
            self._items = _json_list(self._run(["list", "items"]), "list items")
        return self._items

    @staticmethod
    def _exact_one(candidates: Iterable[dict], description: str) -> dict | None:
        found = list(candidates)
        if len(found) > 1:
            raise ResolutionError(f"ambiguous {description}")
        return found[0] if found else None

    def _direct_item(self, reference: OpReference) -> dict | None:
        organization = self._exact_one(
            (org for org in self._organizations_list() if org.get("name") == reference.organization),
            f"organization for {reference.item_uri}",
        )
        if organization is None:
            return None
        organization_id = organization.get("id")
        if not isinstance(organization_id, str) or not organization_id:
            raise ResolutionError(f"invalid organization metadata for {reference.item_uri}")
        return self._exact_one(
            (item for item in self._items_list()
             if item.get("organizationId") == organization_id and item.get("name") == reference.item),
            f"item for {reference.item_uri}",
        )

    def _uri_fallback_item(self, reference: OpReference) -> dict | None:
        def matches(item: dict) -> bool:
            login = item.get("login")
            uris = login.get("uris", []) if isinstance(login, dict) else []
            return any(
                isinstance(uri, dict) and uri.get("uri") in (reference.item_uri, reference.uri)
                for uri in uris
            )
        return self._exact_one(
            (item for item in self._items_list() if matches(item)),
            f"URI fallback item for {reference.item_uri}",
        )

    @staticmethod
    def _field(item: dict, reference: OpReference) -> str:
        custom = [field for field in item.get("fields", []) or []
                  if isinstance(field, dict) and field.get("name") == reference.field]
        if len(custom) > 1:
            raise ResolutionError(f"ambiguous field for {reference.uri}")
        if custom:
            value = custom[0].get("value")
            if isinstance(value, str) and value:
                return value
            raise ResolutionError(f"empty field for {reference.uri}")
        login = item.get("login") if isinstance(item.get("login"), dict) else {}
        if reference.field in ("username", "password"):
            value = login.get(reference.field)
            if isinstance(value, str) and value:
                return value
        if reference.field in ("notes", "note"):
            value = item.get("notes")
            if isinstance(value, str) and value:
                return value
        raise ResolutionError(f"missing field for {reference.uri}")

    def resolve_op_uri(self, uri: str) -> str:
        reference = parse_op_reference(uri)
        item = self._direct_item(reference)
        if item is None:
            item = self._uri_fallback_item(reference)
        if item is None:
            raise ResolutionError(f"missing item for {reference.item_uri}")
        return self._field(item, reference)

    def resolve_bw_uri(self, uri: str) -> str:
        """Retain the simple historical ``bw://org/item/field`` form."""
        if URIParser.parse_bw_uri(uri) is None:
            raise ResolutionError(f"invalid bw:// reference: {uri}")
        parts = uri.removeprefix("bw://").split("/")
        organization, item_name, field = parts[0], parts[-2], parts[-1]
        reference = OpReference(organization, item_name, field)
        item = self._direct_item(reference)
        if item is None:
            raise ResolutionError(f"missing item for bw://{organization}/{item_name}")
        return self._field(item, reference)

    def resolve(self, uri: str) -> str:
        if URIParser.is_op_uri(uri):
            return self.resolve_op_uri(uri)
        if URIParser.is_bw_uri(uri):
            return self.resolve_bw_uri(uri)
        raise ResolutionError(f"unsupported secret reference: {uri}")


class BitwardenClient(VaultResolver):
    """Legacy name retained for programs importing bwenv as a Python module."""


class EnvironmentProcessor:
    """Resolve environment variables whose complete value is a secret reference."""

    def __init__(self, client: VaultResolver):
        self.client = client

    def resolve_environment(self, environment: Mapping[str, str]) -> dict[str, str]:
        resolved = dict(environment)
        for name, value in environment.items():
            if isinstance(value, str) and URIParser.is_supported_uri(value):
                resolved[name] = self.client.resolve(value)
        return resolved


def render_template(content: str, resolver: VaultResolver) -> str:
    """Replace braced and bare op:// references, failing on the first missing one."""
    def replace(match: re.Match[str]) -> str:
        return resolver.resolve(match.group(1) or match.group(2))
    return TEMPLATE_REFERENCE_PATTERN.sub(replace, content)


def parse_file_mode(value: str) -> int:
    try:
        mode = int(value, 8)
    except ValueError as error:
        raise argparse.ArgumentTypeError("file mode must be an octal value") from error
    if not 0 <= mode <= 0o777:
        raise argparse.ArgumentTypeError("file mode must be between 0000 and 0777")
    return mode


def write_output(path: Path, content: str, *, mode: int, force: bool,
                 prompt: Callable[[str], bool] | None = None) -> None:
    """Atomically replace an output file without exposing a partial secret."""
    if path.exists() and not force:
        if prompt is None:
            if not sys.stdin.isatty():
                raise OutputExistsError(f"refusing to overwrite existing file: {path}")
            prompt = lambda question: input(question).strip().lower() in {"y", "yes", "o", "oui"}
        if not prompt(f"Overwrite {path}? [y/N] "):
            raise OutputExistsError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def run_command(command: Sequence[str], environment: Mapping[str, str], resolver: VaultResolver,
                runner: Callable[[Sequence[str], Mapping[str, str]], int] | None = None) -> int:
    if not command:
        raise BWEnvError("run requires a command")
    resolved = EnvironmentProcessor(resolver).resolve_environment(environment)
    resolved.pop("BW_SESSION", None)
    if runner is None:
        return subprocess.run(list(command), env=resolved, check=False).returncode
    return runner(command, resolved)


def _default_security_runner(args: list[str]) -> str:
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise KeychainError("macOS security command was not found") from error
    if result.returncode != 0:
        raise KeychainError("macOS Keychain operation failed")
    return result.stdout


class KeychainSessionStore:
    """Small macOS Keychain adapter; it never logs stored session values."""

    def __init__(self, service: str, *, runner: Callable[[list[str]], str] = _default_security_runner):
        if not service:
            raise KeychainError("a Keychain service name is required")
        self.service = service
        self.runner = runner

    def get(self) -> str:
        value = self.runner(
            ["security", "find-generic-password", "-s", self.service, "-a", KEYCHAIN_ACCOUNT, "-w"]
        ).strip()
        if not value:
            raise KeychainError("Keychain session is empty")
        return value

    def set(self, session: str) -> None:
        if not session:
            raise KeychainError("refusing to store an empty session")
        self.runner(["security", "add-generic-password", "-U", "-s", self.service,
                     "-a", KEYCHAIN_ACCOUNT, "-w", session])

    def delete(self) -> None:
        self.runner(["security", "delete-generic-password", "-s", self.service,
                     "-a", KEYCHAIN_ACCOUNT])


def _unlock_session() -> str:
    try:
        result = subprocess.run(
            ["bw", "unlock", "--raw"],
            check=False,
            stdout=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise BWEnvError("Bitwarden CLI 'bw' was not found") from error
    if result.returncode != 0 or not result.stdout.strip():
        raise BWEnvError("Bitwarden unlock failed")
    return result.stdout.strip()


def _resolver_from_args(args: argparse.Namespace) -> VaultResolver:
    session = KeychainSessionStore(args.keychain_service).get() if args.keychain_service else None
    return VaultResolver(session=session, sync=not args.no_sync)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-sync", action="store_true", help="do not run bw sync before resolving")
    parser.add_argument("--keychain-service", help="read BW_SESSION from this macOS Keychain service")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bwenv")
    _add_common_arguments(parser)
    commands = parser.add_subparsers(dest="command", required=True)
    read = commands.add_parser("read", help="write one secret value to stdout")
    read.add_argument("uri")
    run = commands.add_parser("run", help="run a command with resolved environment variables")
    run.add_argument("command_args", nargs=argparse.REMAINDER)
    inject = commands.add_parser("inject", help="inject op:// references into a template")
    inject.add_argument("-i", "--in-file", type=Path)
    inject.add_argument("-o", "--out-file", type=Path)
    inject.add_argument("--file-mode", type=parse_file_mode, default=0o600)
    inject.add_argument("-f", "--force", action="store_true")
    keychain = commands.add_parser("keychain", help="manage a BW_SESSION in the macOS Keychain")
    keychain_commands = keychain.add_subparsers(dest="keychain_command", required=True)
    for name in ("set-session", "delete-session", "status"):
        command = keychain_commands.add_parser(name)
        command.add_argument("--service", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "keychain":
            store = KeychainSessionStore(args.service)
            if args.keychain_command == "set-session":
                store.set(_unlock_session())
            elif args.keychain_command == "delete-session":
                store.delete()
            else:
                store.get()
            return 0
        resolver = _resolver_from_args(args)
        if args.command == "read":
            print(resolver.resolve(args.uri))
            return 0
        if args.command == "run":
            command_args = args.command_args[1:] if args.command_args[:1] == ["--"] else args.command_args
            return run_command(command_args, os.environ, resolver)
        if args.command == "inject":
            content = args.in_file.read_text(encoding="utf-8") if args.in_file else sys.stdin.read()
            rendered = render_template(content, resolver)
            if args.out_file is None:
                sys.stdout.write(rendered)
            else:
                write_output(args.out_file, rendered, mode=args.file_mode, force=args.force)
            return 0
        raise BWEnvError("unknown command")
    except BWEnvError as error:
        print(f"bwenv: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
