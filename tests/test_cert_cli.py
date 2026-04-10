import json
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from hexssl_cli.cli import app
from hexssl_cli.core import ExitCode
from hexssl_cli.modules.cert.check import CertificateDetails


class CertCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_cert_check_text_output(self) -> None:
        with patch(
            "hexssl_cli.modules.cert.commands.inspect_certificate",
            return_value=_make_details(),
        ):
            result = self.runner.invoke(app, ["cert", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.OK))
        self.assertIn("HEXSSL-CLI certificate check for: example.com", result.stdout)
        self.assertIn("Certificate is valid for the requested host.", result.stdout)
        self.assertIn("Issuer", result.stdout)
        self.assertIn("trusted", result.stdout)

    def test_cert_check_json_output(self) -> None:
        with patch(
            "hexssl_cli.modules.cert.commands.inspect_certificate",
            return_value=_make_details(),
        ):
            result = self.runner.invoke(app, ["cert", "check", "example.com", "--json"])

        self.assertEqual(result.exit_code, int(ExitCode.OK))
        payload = json.loads(result.stdout)
        self.assertEqual(
            set(payload.keys()),
            {"target", "status", "summary", "fields", "issues", "data"},
        )
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["summary"], "Certificate is valid for the requested host.")
        self.assertEqual(payload["issues"], [])
        self.assertEqual(payload["data"]["issuer"], "CN=Example CA")
        self.assertEqual(payload["data"]["sans"], ["example.com", "www.example.com"])
        self.assertEqual(payload["data"]["days_remaining"], 45)
        self.assertTrue(payload["data"]["hostname_valid"])
        self.assertEqual(payload["data"]["chain_verdict"], "trusted")

    def test_cert_check_fail_exit_code(self) -> None:
        with patch(
            "hexssl_cli.modules.cert.commands.inspect_certificate",
            return_value=_make_details(days_remaining=-2),
        ):
            result = self.runner.invoke(app, ["cert", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.ISSUES_FOUND))
        self.assertIn("Certificate has expired.", result.stdout)


def _make_details(days_remaining: int = 45) -> CertificateDetails:
    return CertificateDetails(
        issuer="CN=Example CA",
        sans=["example.com", "www.example.com"],
        not_after="2030-01-01T00:00:00+00:00",
        days_remaining=days_remaining,
        hostname_valid=True,
        hostname_error=None,
        chain_ok=True,
        chain_verdict="trusted",
        chain_error=None,
    )


if __name__ == "__main__":
    unittest.main()
