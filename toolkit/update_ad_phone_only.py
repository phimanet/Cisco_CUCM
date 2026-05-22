import csv
import datetime
import io

try:
    from .ad_phone_fields import update_ad_phone_fields, clear_ad_phone_fields
except ImportError:
    from ad_phone_fields import update_ad_phone_fields, clear_ad_phone_fields


def _write_error_csv(error_message):
    """Return CSV error format."""
    out = io.StringIO()
    log_writer = csv.writer(out)
    log_writer.writerow(["Step", "Status", "Details"])
    log_writer.writerow(["AD Phone Update", "Error", error_message])
    filename = f"ad_phone_update_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return out.getvalue().encode("utf-8"), filename


def update_ad_phone_fields_only(
    target_user,
    phone_number,
    ad_username="",
    ad_password="",
):
    """
    Update AD phone fields (telephoneNumber and ipPhone) only.
    
    If phone_number is blank, clear both fields.
    Returns (csv_data, filename) tuple.
    """
    if not target_user or not target_user.strip():
        return _write_error_csv("target_user is required")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ad_phone_update_{ts}.csv"

    out = io.StringIO()
    log_writer = csv.writer(out)
    log_writer.writerow(["Step", "Status", "Details"])

    try:
        ad_context = None
        if ad_username and ad_password:
            ad_context = {
                "username": ad_username,
                "password": ad_password,
            }

        phone_value = (phone_number or "").strip()

        if phone_value:
            # Update phone fields
            success, message = update_ad_phone_fields(target_user, phone_value, ad_context)
            log_writer.writerow([
                "Update AD Phone Fields",
                "Success" if success else "Failed",
                message,
            ])
        else:
            # Clear phone fields
            success, message = clear_ad_phone_fields(target_user, ad_context)
            log_writer.writerow([
                "Clear AD Phone Fields",
                "Success" if success else "Failed",
                message,
            ])

    except Exception as e:
        log_writer.writerow(["Script", "Error", str(e)])

    return out.getvalue().encode("utf-8"), filename
