import json
import unittest
from typing import List, Optional
from unittest.mock import patch

from typer.testing import CliRunner

from hexssl_cli.cli import app
from hexssl_cli.core import ExitCode
from hexssl_cli.modules.mail.check import MailDetails


class MailCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_mail_check_ok_path(self) -> None:
        with patch(
            "hexssl_cli.modules.mail.commands.inspect_mail",
            return_value=_make_details(),
        ):
            result = self.runner.invoke(
                app,
                ["mail", "check", "example.com", "--selector", "default"],
            )

        self.assertEqual(result.exit_code, int(ExitCode.OK))
        self.assertIn("HEXSSL-CLI mail check for: example.com", result.stdout)
        self.assertIn("Mail trust records look operational.", result.stdout)
        self.assertIn("DMARC Policy", result.stdout)

    def test_mail_check_warning_path(self) -> None:
        with patch(
            "hexssl_cli.modules.mail.commands.inspect_mail",
            return_value=_make_details(
                dmarc_policy="none",
                dmarc_issue="weak_policy",
            ),
        ):
            result = self.runner.invoke(
                app,
                ["mail", "check", "example.com", "--selector", "default"],
            )

        self.assertEqual(result.exit_code, int(ExitCode.WARNING))
        self.assertIn("Mail trust records are present, but enforcement is weak.", result.stdout)
        self.assertIn("weak_dmarc_policy", result.stdout)

    def test_mail_check_fail_path(self) -> None:
        with patch(
            "hexssl_cli.modules.mail.commands.inspect_mail",
            return_value=_make_details(
                spf_records=[],
                spf_valid=False,
                spf_issue="missing",
                dmarc_record=None,
                dmarc_valid=False,
                dmarc_policy=None,
                dmarc_issue="missing",
                dkim_record=None,
                dkim_valid=False,
                dkim_issue="missing",
            ),
        ):
            result = self.runner.invoke(
                app,
                ["mail", "check", "example.com", "--selector", "default"],
            )

        self.assertEqual(result.exit_code, int(ExitCode.ISSUES_FOUND))
        self.assertIn("Mail trust records need corrective action.", result.stdout)
        self.assertIn("missing_spf", result.stdout)
        self.assertIn("missing_dmarc", result.stdout)
        self.assertIn("missing_dkim", result.stdout)

    def test_mail_check_json_output(self) -> None:
        with patch(
            "hexssl_cli.modules.mail.commands.inspect_mail",
            return_value=_make_details(),
        ):
            result = self.runner.invoke(
                app,
                ["mail", "check", "example.com", "--selector", "default", "--json"],
            )

        self.assertEqual(result.exit_code, int(ExitCode.OK))
        payload = json.loads(result.stdout)
        self.assertEqual(
            set(payload.keys()),
            {"target", "status", "summary", "fields", "issues", "data"},
        )
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["data"]["selector"], "default")
        self.assertEqual(payload["data"]["spf"]["records"], ["v=spf1 include:_spf.example.net -all"])
        self.assertEqual(payload["data"]["dmarc"]["policy"], "reject")
        self.assertTrue(payload["data"]["dkim"]["valid"])


def _make_details(
    spf_records: Optional[List[str]] = None,
    spf_valid: bool = True,
    spf_issue: Optional[str] = None,
    dmarc_record: Optional[str] = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    dmarc_valid: bool = True,
    dmarc_policy: Optional[str] = "reject",
    dmarc_issue: Optional[str] = None,
    dkim_record: Optional[str] = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
    dkim_valid: bool = True,
    dkim_issue: Optional[str] = None,
) -> MailDetails:
    return MailDetails(
        selector="default",
        spf_records=["v=spf1 include:_spf.example.net -all"] if spf_records is None else spf_records,
        spf_valid=spf_valid,
        spf_issue=spf_issue,
        dmarc_record=dmarc_record,
        dmarc_valid=dmarc_valid,
        dmarc_policy=dmarc_policy,
        dmarc_issue=dmarc_issue,
        dkim_record=dkim_record,
        dkim_valid=dkim_valid,
        dkim_issue=dkim_issue,
    )


if __name__ == "__main__":
    unittest.main()
