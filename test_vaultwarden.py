#!/usr/bin/env python3
"""Contract tests for the Vaultwarden-compatible op:// resolver."""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import bwenv


class FakeBW:
    def __init__(self, organizations, items):
        self.organizations = organizations
        self.items = items
        self.calls = []

    def __call__(self, args, env):
        self.calls.append((args, env.copy()))
        if args == ["status"]:
            return '{"status":"unlocked"}'
        if args == ["sync"]:
            return ""
        if args == ["list", "organizations"]:
            return bwenv.json.dumps(self.organizations)
        if args == ["list", "items"]:
            return bwenv.json.dumps(self.items)
        raise AssertionError(f"unexpected bw command: {args}")


def item(name, organization_id, fields=None, username=None, password=None, uris=None):
    return {
        "name": name,
        "organizationId": organization_id,
        "fields": fields or [],
        "login": {"username": username, "password": password, "uris": uris or []},
        "notes": "notes-value",
    }


class VaultResolverTests(unittest.TestCase):
    def setUp(self):
        self.orgs = [{"id": "infra-id", "name": "Infra"}]
        self.items = [
            item(
                "service",
                "infra-id",
                fields=[{"name": "token", "value": "custom-token"}],
                username="login-user",
                password="login-password",
            )
        ]

    def resolver(self, organizations=None, items=None):
        return bwenv.VaultResolver(
            runner=FakeBW(organizations or self.orgs, items or self.items), sync=False
        )

    def test_direct_lookup_prefers_custom_fields(self):
        self.assertEqual(
            "custom-token", self.resolver().resolve("op://Infra/service/token")
        )

    def test_direct_lookup_supports_standard_login_and_notes_fields(self):
        resolver = self.resolver()
        self.assertEqual("login-user", resolver.resolve("op://Infra/service/username"))
        self.assertEqual("login-password", resolver.resolve("op://Infra/service/password"))
        self.assertEqual("notes-value", resolver.resolve("op://Infra/service/notes"))

    def test_uri_metadata_is_a_fallback_only(self):
        resolver = self.resolver(
            organizations=[],
            items=[
                item(
                    "renamed-item",
                    "other-org",
                    fields=[{"name": "token", "value": "fallback-token"}],
                    uris=[{"uri": "op://Infra/service"}],
                )
            ],
        )
        self.assertEqual("fallback-token", resolver.resolve("op://Infra/service/token"))

    def test_ambiguous_item_fails_closed(self):
        duplicate = item("service", "infra-id", fields=[{"name": "token", "value": "other"}])
        with self.assertRaisesRegex(bwenv.ResolutionError, "ambiguous"):
            self.resolver(items=self.items + [duplicate]).resolve("op://Infra/service/token")

    def test_missing_field_does_not_expose_a_secret(self):
        with self.assertRaisesRegex(bwenv.ResolutionError, "op://Infra/service/missing") as raised:
            self.resolver().resolve("op://Infra/service/missing")
        self.assertNotIn("custom-token", str(raised.exception))

    def test_simple_bw_uri_remains_supported(self):
        self.assertEqual(
            "custom-token", self.resolver().resolve("bw://Infra/service/token")
        )


class InjectTests(unittest.TestCase):
    def setUp(self):
        self.resolver = bwenv.VaultResolver(
            runner=FakeBW(
                [{"id": "infra-id", "name": "Infra"}],
                [
                    item(
                        "service",
                        "infra-id",
                        fields=[{"name": "token", "value": "custom-token"}],
                        password="login-password",
                    )
                ],
            ),
            sync=False,
        )

    def test_template_supports_bare_and_braced_references(self):
        rendered = bwenv.render_template(
            "a={{ op://Infra/service/token }}\nb=op://Infra/service/password\n",
            self.resolver,
        )
        self.assertEqual("a=custom-token\nb=login-password\n", rendered)

    def test_atomic_output_requires_force_and_uses_requested_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "runtime.env"
            target.write_text("old", encoding="utf-8")
            with self.assertRaises(bwenv.OutputExistsError):
                bwenv.write_output(target, "new", mode=0o600, force=False, prompt=lambda _: False)
            bwenv.write_output(target, "new", mode=0o600, force=True)
            self.assertEqual("new", target.read_text(encoding="utf-8"))
            self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_cli_inject_writes_a_restricted_file(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "runtime.env.tpl"
            output = Path(directory) / "runtime.env"
            template.write_text("TOKEN={{ op://Infra/service/token }}\n", encoding="utf-8")
            with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver):
                self.assertEqual(
                    0,
                    bwenv.main(["--no-sync", "inject", "-i", str(template), "-o", str(output)]),
                )
            self.assertEqual("TOKEN=custom-token\n", output.read_text(encoding="utf-8"))
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))

    def test_cli_refusal_does_not_print_injected_value(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "runtime.env.tpl"
            output = Path(directory) / "runtime.env"
            template.write_text("TOKEN=op://Infra/service/token\n", encoding="utf-8")
            output.write_text("old", encoding="utf-8")
            stderr = StringIO()
            with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver), redirect_stderr(stderr):
                self.assertEqual(
                    1,
                    bwenv.main(["--no-sync", "inject", "-i", str(template), "-o", str(output)]),
                )
            self.assertNotIn("custom-token", stderr.getvalue())

    def test_run_strips_bw_session_before_starting_the_child(self):
        received = {}

        def child_runner(command, env):
            received["command"] = command
            received["env"] = env
            return 0

        bwenv.run_command(
            ["example-service"],
            {"TOKEN": "op://Infra/service/token", "BW_SESSION": "session-sentinel"},
            self.resolver,
            child_runner,
        )
        self.assertEqual("custom-token", received["env"]["TOKEN"])
        self.assertNotIn("BW_SESSION", received["env"])

    def test_run_parser_keeps_command_arguments_after_separator(self):
        with patch.object(bwenv, "_resolver_from_args", return_value=self.resolver), patch.object(
            bwenv, "run_command", return_value=0
        ) as run_command:
            self.assertEqual(0, bwenv.main(["run", "--", "example-service", "--flag"]))
        self.assertEqual(["example-service", "--flag"], list(run_command.call_args.args[0]))


class KeychainTests(unittest.TestCase):
    def test_keychain_session_is_read_without_echoing_its_value(self):
        calls = []

        def runner(args):
            calls.append(args)
            return "session-sentinel"

        store = bwenv.KeychainSessionStore("bwenv.vaultwarden", runner=runner)
        self.assertEqual("session-sentinel", store.get())
        self.assertEqual(
            ["security", "find-generic-password", "-s", "bwenv.vaultwarden", "-a", "BW_SESSION", "-w"],
            calls[0],
        )

    @patch("bwenv.subprocess.run")
    def test_unlock_captures_only_the_session_not_the_interactive_prompt(self, mocked_run):
        mocked_run.return_value = type("Result", (), {"returncode": 0, "stdout": "session-sentinel\n"})()
        self.assertEqual("session-sentinel", bwenv._unlock_session())
        _, kwargs = mocked_run.call_args
        self.assertEqual(subprocess.PIPE, kwargs["stdout"])
        self.assertNotIn("capture_output", kwargs)


class ProcessIntegrationTests(unittest.TestCase):
    def test_inject_uses_a_bw_executable_from_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bw = root / "bw"
            fake_bw.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                "if args == ['status']:\n"
                "    print(json.dumps({'status': 'unlocked'}))\n"
                "elif args == ['list', 'organizations']:\n"
                "    print(json.dumps([{'id': 'infra-id', 'name': 'Infra'}]))\n"
                "elif args == ['list', 'items']:\n"
                "    print(json.dumps([{'name': 'service', 'organizationId': 'infra-id', 'fields': [{'name': 'token', 'value': 'subprocess-token'}], 'login': {}}]))\n"
                "else:\n"
                "    print('SENTINEL_SECRET_FROM_BW_STDERR', file=sys.stderr)\n"
                "    raise SystemExit(12)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o755)
            environment = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
            result = subprocess.run(
                [sys.executable, str(Path(bwenv.__file__)), "--no-sync", "inject"],
                input="TOKEN={{ op://Infra/service/token }}\n",
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("TOKEN=subprocess-token\n", result.stdout)
            self.assertNotIn("SENTINEL_SECRET_FROM_BW_STDERR", result.stderr)


if __name__ == "__main__":
    unittest.main()
