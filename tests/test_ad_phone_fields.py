import csv
import importlib.util
import io
import os
import unittest
from unittest.mock import patch

from toolkit import ad_phone_fields as fields
from toolkit import update_ad_phone_only as standalone


class ADPhoneLDAPCredentialsTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("ldap3"), "ldap3 is optional")
    def test_installed_ldap3_enables_transport_and_sid_formatter(self):
        self.assertTrue(fields.LDAP3_AVAILABLE)
        self.assertEqual(
            fields._sid_to_string(bytes.fromhex("010100000000000520000000")),
            "S-1-5-32",
        )

    def test_phone_and_email_lookups_use_matching_credentials(self):
        config = {"upn_suffix": "example.test", "default_domain": ""}
        session = {"username": "operator", "password": "session-password"}
        cases = [
            ({}, session, "operator@example.test", "session-password"),
            ({"AD_LDAP_BIND_USER": "service", "AD_LDAP_BIND_PASSWORD": "service-password"},
             session, "service@example.test", "service-password"),
            ({"AD_LDAP_BIND_USER": "service", "AD_LDAP_BIND_PASSWORD": "service-password"},
             None, "service@example.test", "service-password"),
        ]
        for lookup, identity in (
            (fields._lookup_ad_user_ldapsearch, "Test.User"),
            (fields._resolve_samaccountname_by_email_ldapsearch, "test@example.test"),
        ):
            for overrides, context, username, password in cases:
                with self.subTest(lookup=lookup.__name__, service=bool(overrides), session=bool(context)), \
                        patch.dict(os.environ, overrides, clear=True), \
                        patch.object(fields, "_resolve_ldap_config", return_value=(config, "")), \
                        patch.object(fields, "_run_ldapsearch_query", return_value=(
                            {"distinguishedName": ["CN=Test"], "sAMAccountName": ["Test.User"]}, ""
                        )) as query:
                    result, error = lookup(identity, context)
                    self.assertEqual(error, "")
                    self.assertTrue(result["found"])
                    self.assertEqual(query.call_args.args[1:3], (username, password))

    def test_incomplete_service_credentials_block_lookup_and_modification(self):
        for overrides in (
            {"AD_LDAP_BIND_USER": "service"},
            {"AD_LDAP_BIND_PASSWORD": "service-password"},
        ):
            with self.subTest(overrides=list(overrides)), \
                    patch.dict(os.environ, overrides, clear=True), \
                    patch.object(fields, "_resolve_ldap_config", return_value=({}, "")), \
                    patch.object(fields, "_run_ldapsearch_query") as query, \
                    patch.object(fields.subprocess, "run") as run:
                context = {"username": "operator", "password": "session-password"}
                for lookup, identity in (
                    (fields._lookup_ad_user_ldapsearch, "Test.User"),
                    (fields._resolve_samaccountname_by_email_ldapsearch, "test@example.test"),
                ):
                    result, error = lookup(identity, context)
                    self.assertIsNone(result)
                    self.assertIn("must be set together", error)
                error = fields._run_ldapmodify_attributes(
                    "CN=Test", context, replace_attrs={"telephoneNumber": "123"}
                )
                self.assertIn("must be set together", error)
                query.assert_not_called()
                run.assert_not_called()

    def test_service_credentials_match_through_phone_update_and_clear(self):
        config = {"upn_suffix": "example.test", "default_domain": ""}
        for runner, args in (
            (fields.update_ad_phone_fields, ("Test.User", "8585236648")),
            (fields.clear_ad_phone_fields, ("Test.User",)),
        ):
            with self.subTest(runner=runner.__name__), \
                    patch.dict(os.environ, {
                        "AD_LDAP_BIND_USER": "service",
                        "AD_LDAP_BIND_PASSWORD": "service-password",
                    }, clear=True), \
                    patch.object(fields, "_resolve_ldap_config", return_value=(config, "")), \
                    patch.object(fields, "_run_powershell_json", return_value=(None, "Unavailable")), \
                    patch.object(fields, "LDAP3_AVAILABLE", False), \
                    patch.object(fields, "_run_ldapsearch_query", return_value=(
                        {"distinguishedName": ["CN=Test"]}, ""
                    )) as query, \
                    patch.object(fields, "_resolve_ldapmodify_executable", return_value="ldapmodify"), \
                    patch.object(fields, "_ldap_uri_candidates", return_value=["ldaps://directory.example.test:636"]), \
                    patch.object(fields.subprocess, "run") as run:
                run.return_value.returncode = 0
                success, message = runner(
                    *args, auth_context={"username": "operator", "password": "session-password"}
                )
                self.assertTrue(success, message)
                self.assertEqual(query.call_args.args[1:3], ("service@example.test", "service-password"))
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("-D") + 1], "service@example.test")
                self.assertEqual(command[command.index("-w") + 1], "service-password")


class ADPhoneFormatTests(unittest.TestCase):
    def test_business_number_format_and_idempotence(self):
        for value in ("8585236648", "858-523-6648", "(858) 523-6648", "18585236648", "+1-858-523-6648", "+1(858)5236648", "+1 (858) 5236648"):
            self.assertEqual(fields._format_phone_dashes(value), "+1 (858) 5236648", value)
        self.assertEqual(fields._format_phone_dashes("6194104147"), "+1 (619) 4104147")

    def test_other_lengths_and_ipphone_format_are_unchanged(self):
        self.assertEqual(fields._format_phone_dashes("6648"), "6648")
        self.assertEqual(fields._format_phone_dashes(""), "")
        self.assertEqual(fields._format_phone_plain("858-523-6648"), "8585236648")
        self.assertEqual(fields._format_phone_plain("+1-858-523-6648"), "18585236648")
        self.assertEqual(fields._format_phone_plain("+1 (619) 4104147"), "16194104147")

    def test_all_update_transports_use_country_code_only_for_telephone(self):
        expected = {"telephoneNumber": "+1 (858) 5236648", "ipPhone": "8585236648"}
        for transport in ("powershell", "ldap", "ldapmodify"):
            with self.subTest(transport=transport), \
                    patch.object(fields, "_lookup_ad_user", return_value=({"found": True, "distinguishedName": "CN=Test"}, "")), \
                    patch.object(fields, "_run_powershell_json", return_value=({}, "Unavailable" if transport != "powershell" else "")) as powershell, \
                    patch.object(fields, "_run_ldap_modify", return_value="Unavailable" if transport == "ldapmodify" else "") as ldap, \
                    patch.object(fields, "_run_ldapmodify_attributes", return_value="") as ldapmodify:
                success, message = fields.update_ad_phone_fields("Test.User", "8585236648")
                self.assertTrue(success, message)
                payload = powershell.call_args.args[1]
                self.assertEqual({key: payload[key] for key in expected}, expected)
                if transport != "powershell":
                    self.assertEqual(ldap.call_args.kwargs["replace_attrs"], expected)
                if transport == "ldapmodify":
                    self.assertEqual(ldapmodify.call_args.kwargs["replace_attrs"], expected)

    def test_standalone_username_and_email_reuse_shared_formatter(self):
        with patch.object(fields, "_lookup_ad_user", return_value=({"found": True, "distinguishedName": "CN=Test"}, "")), \
                patch.object(fields, "_run_powershell_json", return_value=({}, "")) as powershell, \
                patch.object(standalone, "resolve_samaccountname_by_email", return_value=("Test.User", "Found")):
            for runner, identity in ((standalone.update_ad_phone_fields_only, "Test.User"),
                                     (standalone.update_ad_phone_fields_by_email, "test@example.test")):
                data, filename = runner(identity, "8585236648")
                rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
                self.assertEqual(rows[-1][1], "Success")
                self.assertIn("telephoneNumber=+1 (858) 5236648", rows[-1][2])
                self.assertEqual(powershell.call_args.args[1]["ipPhone"], "8585236648")

    def test_blank_standalone_value_still_clears_both_fields(self):
        with patch.object(standalone, "clear_ad_phone_fields", return_value=(True, "Cleared")) as clear, \
                patch.object(standalone, "update_ad_phone_fields") as update:
            standalone.update_ad_phone_fields_only("Test.User", "")
            clear.assert_called_once_with("Test.User", None)
            update.assert_not_called()


if __name__ == "__main__":
    unittest.main()