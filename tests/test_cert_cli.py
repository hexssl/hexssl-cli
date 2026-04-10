import json
import ssl
import unittest
from re import sub
from typing import Optional
from unittest.mock import patch

from typer.testing import CliRunner

from hexssl_cli.cli import app
from hexssl_cli.core import ExitCode
from hexssl_cli.modules.cert.check import CertificateDetails, _format_certificate_error


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

    def test_cert_check_expired_certificate_result(self) -> None:
        with patch(
            "hexssl_cli.modules.cert.commands.inspect_certificate",
            return_value=_make_details(days_remaining=-2),
        ):
            result = self.runner.invoke(app, ["cert", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.ISSUES_FOUND))
        self.assertIn("Certificate has expired.", result.stdout)
        self.assertIn("certificate_expired", result.stdout)

    def test_cert_check_hostname_mismatch_result(self) -> None:
        with patch(
            "hexssl_cli.modules.cert.commands.inspect_certificate",
            return_value=_make_details(
                hostname_valid=False,
                hostname_error="hostname 'example.com' doesn't match 'wrong.host.badssl.com'",
            ),
        ):
            result = self.runner.invoke(app, ["cert", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.ISSUES_FOUND))
        self.assertIn("Certificate does not match the requested hostname.", result.stdout)
        self.assertIn("hostname_mismatch", result.stdout)
        normalized_output = _normalize_whitespace(result.stdout)
        self.assertIn(
            "hostname 'example.com' doesn't match 'wrong.host.badssl.com'",
            normalized_output,
        )

    def test_cert_check_self_signed_result(self) -> None:
        with patch(
            "hexssl_cli.modules.cert.commands.inspect_certificate",
            return_value=_make_details(
                chain_ok=False,
                chain_verdict="untrusted",
                chain_error="self signed certificate",
            ),
        ):
            result = self.runner.invoke(app, ["cert", "check", "example.com"])

        self.assertEqual(result.exit_code, int(ExitCode.ISSUES_FOUND))
        self.assertIn("Certificate chain could not be verified.", result.stdout)
        self.assertIn("chain_verification_failed", result.stdout)
        self.assertIn("self signed certificate", result.stdout)

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

    def test_format_certificate_error_returns_clean_message(self) -> None:
        exc = ssl.CertificateError(
            "hostname 'example.com' doesn't match 'wrong.host.badssl.com'",
            {"subject": ((("commonName", "wrong.host.badssl.com"),),)},
        )

        message = _format_certificate_error(exc)

        self.assertEqual(
            message,
            "hostname 'example.com' doesn't match 'wrong.host.badssl.com'",
        )


def _make_details(
    days_remaining: int = 45,
    hostname_valid: bool = True,
    hostname_error: Optional[str] = None,
    chain_ok: bool = True,
    chain_verdict: str = "trusted",
    chain_error: Optional[str] = None,
) -> CertificateDetails:
    return CertificateDetails(
        issuer="CN=Example CA",
        sans=["example.com", "www.example.com"],
        not_after="2030-01-01T00:00:00+00:00",
        days_remaining=days_remaining,
        hostname_valid=hostname_valid,
        hostname_error=hostname_error,
        chain_ok=chain_ok,
        chain_verdict=chain_verdict,
        chain_error=chain_error,
    )


def _normalize_whitespace(value: str) -> str:
    return sub(r"\s+", " ", value).strip()


if __name__ == "__main__":
    unittest.main()
