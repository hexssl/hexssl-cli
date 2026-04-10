import json
import unittest
from typing import Optional
from unittest.mock import patch

from typer.testing import CliRunner

from hexssl_cli.cli import app
from hexssl_cli.core import ExitCode
from hexssl_cli.modules.dns.check import DNSDetails


class DNSCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_dns_check_text_output_ok(self) -> None:
        with patch(
            "hexssl_cli.modules.dns.commands.inspect_dns",
            return_value=_make_details(),
        ):
            result = self.runner.invoke(app, ["dns", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.OK))
        self.assertIn("HEXSSL-CLI DNS check for: example.com", result.stdout)
        self.assertIn("DNS records look operational.", result.stdout)
        self.assertIn("A Records", result.stdout)

    def test_dns_check_warning_output(self) -> None:
        with patch(
            "hexssl_cli.modules.dns.commands.inspect_dns",
            return_value=_make_details(
                caa_records=[],
                apex_www_consistent=False,
                consistency_note="www has no A, AAAA, or CNAME record.",
            ),
        ):
            result = self.runner.invoke(app, ["dns", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.WARNING))
        self.assertIn("missing_caa", result.stdout)
        self.assertIn("www_inconsistent", result.stdout)

    def test_dns_check_fail_output(self) -> None:
        with patch(
            "hexssl_cli.modules.dns.commands.inspect_dns",
            return_value=_make_details(
                a_records=[],
                aaaa_records=[],
                cname=None,
                caa_records=[],
            ),
        ):
            result = self.runner.invoke(app, ["dns", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.ISSUES_FOUND))
        self.assertIn("No usable apex DNS records were found.", result.stdout)
        self.assertIn("apex_unresolved", result.stdout)

    def test_dns_check_json_output(self) -> None:
        with patch(
            "hexssl_cli.modules.dns.commands.inspect_dns",
            return_value=_make_details(),
        ):
            result = self.runner.invoke(app, ["dns", "check", "example.com", "--json"])

        self.assertEqual(result.exit_code, int(ExitCode.OK))
        payload = json.loads(result.stdout)
        self.assertEqual(
            set(payload.keys()),
            {"target", "status", "summary", "fields", "issues", "data"},
        )
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["data"]["apex"]["a_records"], ["192.0.2.10"])
        self.assertEqual(payload["data"]["www"]["cname"], "example.com")
        self.assertTrue(payload["data"]["apex_www_consistent"])


def _make_details(
    a_records=None,
    aaaa_records=None,
    cname: Optional[str] = None,
    caa_records=None,
    www_a_records=None,
    www_aaaa_records=None,
    www_cname: Optional[str] = "example.com",
    apex_www_consistent: bool = True,
    consistency_note: str = "www resolves through CNAME.",
) -> DNSDetails:
    return DNSDetails(
        a_records=["192.0.2.10"] if a_records is None else a_records,
        aaaa_records=["2001:db8::10"] if aaaa_records is None else aaaa_records,
        cname=cname,
        caa_records=['0 issue "letsencrypt.org"'] if caa_records is None else caa_records,
        www_a_records=[] if www_a_records is None else www_a_records,
        www_aaaa_records=[] if www_aaaa_records is None else www_aaaa_records,
        www_cname=www_cname,
        apex_www_consistent=apex_www_consistent,
        consistency_note=consistency_note,
    )


if __name__ == "__main__":
    unittest.main()
