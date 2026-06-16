import os

LAB_CUCM_HOST = "lascucmpl01.ahs.int"
PROD_CUCM_HOST = "lascucmpp01.ahs.int"
LAB_UNITY_HOST = "lascutypl01.ahs.int"
PROD_UNITY_HOST = "SANCUTYP01.ahs.int"
DEFAULT_ROUTE_PARTITION = "ENT_DEVICE_PT"
TEAMS_ROUTE_PARTITION = "ENT_TEAMS_DEVICE_PT"
LAB_CSF_TEMPLATE_FILE = "phone_device_template_lab_csf.json"
TCT_TEMPLATE_FILE = "phone_device_template_tct.json"
BOT_TEMPLATE_FILE = "phone_device_template_bot.json"
DEFAULT_VM_PIN = "56219"
MOBILE_JABBER_EMAIL_FROM = "noreply@amnhealthcare.com"
MOBILE_JABBER_EMAIL_SUBJECT = "Jabber on iPhone or Android - Ready to install"
MOBILE_JABBER_EMAIL_BODY = (
  "Jabber for mobile phones is ready for use.\n\n"
  "You must delete the app on the iPhone/Android first if you have it already installed.\n\n"
  "To setup Jabber on your mobile phone:\n\n"
  "1. Download Cisco Jabber on your mobile phone.\n"
  "2. Go thru the questions and accept Jabber to use the microphone.\n"
  "3. Enter in your AMN Email address.\n"
  "4. Enter in your AMN password.\n"
  "5. If it balks at an invalid certificate, this is OK. Accept or press OK.\n"
  "6. You should now be logged in."
)
CSF_JABBER_EMAIL_FROM = (os.getenv("CSF_JABBER_EMAIL_FROM", MOBILE_JABBER_EMAIL_FROM) or MOBILE_JABBER_EMAIL_FROM).strip()
CSF_JABBER_TRAINING_URL = (
  "https://amnhealthcare.sharepoint.com/teams/AMNITTrainingContent-tm/_layouts/15/stream.aspx?id=%2Fteams%2FAMNITTrainingContent%2Dtm%2FShared%20Documents%2FGeneral%2FWatch%20and%20Learn%20Cisco%20Jabber%20Softphone%2012%2E9%2Emp4&referrer=StreamWebApp%2EWeb&referrerScenario=AddressBarCopied%2Eview%2Ef9fafd5b%2D7aeb%2D4bfb%2Dbc57%2Dda61d14ef75f"
)
TWILIO_INBOUND_VERIFICATION_PROFILES = {
  "phimane": {
    "panel_label": "Twilio-Inbound-Verificaton-Phimane",
    "description": "Twilio Number Verification to Phimane 8585236648",
    "home_pattern": "8585236648",
  },
  "lauraa": {
    "panel_label": "Twilio-Inbound-Verificaton-LauraA",
    "description": "Twilio Number Verification to LauraA 8583503289",
    "home_pattern": "8583503289",
  },
}
ENVIRONMENT_SETTINGS = {
  "LAB": {
    "cucm_host": LAB_CUCM_HOST,
    "unity_host": LAB_UNITY_HOST,
    "route_partition": DEFAULT_ROUTE_PARTITION,
    "template_alias": "T3-CST",
    "default_vm_pin": DEFAULT_VM_PIN,
  },
  "PRODUCTION": {
    "cucm_host": PROD_CUCM_HOST,
    "unity_host": PROD_UNITY_HOST,
    "route_partition": DEFAULT_ROUTE_PARTITION,
    "template_alias": "T3-CST",
    "default_vm_pin": DEFAULT_VM_PIN,
  },
}
