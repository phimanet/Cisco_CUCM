import csv
import importlib.util
import io
import os
import unittest
from unittest.mock import Mock, patch

from toolkit import ad_phone_fields as fields
from toolkit import update_ad_phone_only as standalone


class ADPhoneLDAPCredentialsTests(unittest.TestCase):
    def test_simple_bind_preserves_explicit_identity_and_qualifies_bare_username(self):
        config = {"auth_mode": "simple", "upn_suffix": "example.test", "default_domain": "EXAMPLE"}
        cases = [
            (r"OTHER\operator", "EXAMPLE", "example.test", r"OTHER\operator"),
            ("operator", "EXAMPLE", "example.test", r"EXAMPLE\operator"),
            ("operator@other.test", "EXAMPLE", "example.test", "operator@other.test"),
            (r"EXAMPLE\operator", "EXAMPLE", "", r"EXAMPLE\operator"),
            ("operator", "", "example.test", "operator@example.test"),
            ("operator", "", "", "operator"),
        ]
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(fields, "SIMPLE", "SIMPLE", create=True):
            for username, domain, suffix, expected in cases:
                with self.subTest(username=username, domain=domain, suffix=suffix):
                    config["default_domain"] = domain
                    config["upn_suffix"] = suffix
                    context = {"username": username, "password": "session-password"}
                    self.assertEqual(
                        fields._resolve_ldap_bind_credentials(context, config),
                        (expected, "SIMPLE", ""),
                    )
                    self.assertEqual(fields._resolve_ldapsearch_bind_user(context, config), expected)
                    self.assertEqual(context, {"username": username, "password": "session-password"})

    def test_standalone_python_lookup_and_modify_use_same_cached_domain_identity(self):
        config = {
            "auth_mode": "simple", "upn_suffix": "example.test", "default_domain": "EXAMPLE",
            "server": "directory.example.test", "port": 636, "use_ssl": True, "base_dn": "DC=example,DC=test",
        }
        for username in ("operator", r"EXAMPLE\operator"):
            for phone in ("8585236648", ""):
                with self.subTest(username=username, clearing=not phone):
                    conn = Mock(entries=[Mock(entry_dn="CN=Target")], result={})
                    connection = Mock(return_value=conn)
                    with patch.dict(os.environ, {}, clear=True), \
                            patch.object(fields, "_resolve_ldap_config", return_value=(config, "")), \
                            patch.object(fields, "_run_powershell_json", return_value=(None, "Unavailable")), \
                            patch.multiple(
                                fields, LDAP3_AVAILABLE=True, Server=Mock(), Connection=connection,
                                ALL="ALL", SIMPLE="SIMPLE", SUBTREE="SUBTREE",
                                MODIFY_REPLACE="REPLACE", MODIFY_DELETE="DELETE", create=True,
                            ), \
                            patch.object(fields, "_lookup_ad_user_ldapsearch") as cli:
                        data, _ = standalone.update_ad_phone_fields_only(
                            "Target.User", phone, username, "session-password"
                        )
                        self.assertEqual(list(csv.reader(io.StringIO(data.decode())))[-1][1], "Success")
                        self.assertEqual(connection.call_count, 2)
                        for call in connection.call_args_list:
                            self.assertEqual(call.kwargs["user"], r"EXAMPLE\operator")
                            self.assertEqual(call.kwargs["password"], "session-password")
                            self.assertEqual(call.kwargs["authentication"], "SIMPLE")
                        expected = (
                            {"telephoneNumber": [("REPLACE", ["+1 (858) 5236648"])],
                             "ipPhone": [("REPLACE", ["8585236648"])]}
                            if phone else
                            {"telephoneNumber": [("DELETE", [])], "ipPhone": [("DELETE", [])]}
                        )
                        conn.modify.assert_called_once_with("CN=Target", expected)
                        cli.assert_not_called()

    def test_standalone_cli_lookup_and_modify_preserve_cached_domain_identity(self):
        config = {"upn_suffix": "example.test", "default_domain": "EXAMPLE", "base_dn": "DC=example,DC=test"}
        for username in ("operator", r"EXAMPLE\operator"):
            with self.subTest(username=username), \
                    patch.dict(os.environ, {}, clear=True), \
                    patch.object(fields, "_resolve_ldap_config", return_value=(config, "")), \
                    patch.object(fields, "_run_powershell_json", return_value=(None, "Unavailable")), \
                    patch.object(fields, "LDAP3_AVAILABLE", False), \
                    patch.object(fields, "_resolve_ldapsearch_executable", return_value="ldapsearch"), \
                    patch.object(fields, "_resolve_ldapmodify_executable", return_value="ldapmodify"), \
                    patch.object(fields, "_ldap_uri_candidates", return_value=["ldaps://directory.example.test:636"]), \
                    patch.object(fields.subprocess, "run", side_effect=[
                        fields.subprocess.CompletedProcess([], 0, "dn: CN=Target\n", ""),
                        fields.subprocess.CompletedProcess([], 0, "", ""),
                    ]) as run:
                data, _ = standalone.update_ad_phone_fields_only(
                    "Target.User", "8585236648", username, "session-password"
                )
                self.assertEqual(list(csv.reader(io.StringIO(data.decode())))[-1][1], "Success")
                self.assertEqual(run.call_count, 2)
                for call in run.call_args_list:
                    command = call.args[0]
                    self.assertEqual(command[command.index("-D") + 1], r"EXAMPLE\operator")
                    self.assertEqual(command[command.index("-w") + 1], "session-password")
                self.assertIn("telephoneNumber: +1 (858) 5236648", run.call_args.kwargs["input"])
                self.assertIn("ipPhone: 8585236648", run.call_args.kwargs["input"])

    def test_ntlm_and_auto_keep_cached_domain_username(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(fields, "NTLM", "NTLM", create=True):
            for mode in ("ntlm", "auto"):
                with self.subTest(mode=mode):
                    self.assertEqual(
                        fields._resolve_ldap_bind_credentials(
                            {"username": r"EXAMPLE\operator", "password": "session-password"},
                            {"auth_mode": mode, "upn_suffix": "example.test", "default_domain": "EXAMPLE"},
                        ),
                        (r"EXAMPLE\operator", "NTLM", ""),
                    )

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