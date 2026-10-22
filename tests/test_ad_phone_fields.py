import csv
import io
import unittest
from unittest.mock import patch

from toolkit import ad_phone_fields as fields
from toolkit import update_ad_phone_only as standalone


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