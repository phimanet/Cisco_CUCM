import csv
import io
import re


ROUTE_PARTITION = "ENT_DEVICE_PT"
MAX_DIRECTORY_NUMBERS = 1000
INACTIVE_VALUES = {"f", "false", "0"}


def parse_directory_numbers(raw_numbers, limit=MAX_DIRECTORY_NUMBERS):
    tokens = [token.strip() for token in re.split(r"[,;\s]+", str(raw_numbers or "")) if token.strip()]
    if not tokens:
        raise ValueError("Enter one or more 10-digit Directory Numbers.")

    invalid = [token for token in tokens if not re.fullmatch(r"\d{10}", token)]
    if invalid:
        raise ValueError("Every entry must be an exact 10-digit Directory Number: " + ", ".join(invalid[:10]))

    numbers = list(dict.fromkeys(tokens))
    if len(numbers) > max(1, int(limit)):
        raise ValueError(f"Enter no more than {limit} unique Directory Numbers per request.")
    return numbers


def build_exact_number_sql(numbers):
    clean_numbers = parse_directory_numbers("\n".join(numbers))
    values = ", ".join("'" + number + "'" for number in clean_numbers)
    return (
        "SELECT n.pkid AS line_id, n.dnorpattern AS pattern, "
        "r.name AS route_partition, n.iscallable AS is_active, "
        "m.fkdevice AS device_id, d.name AS device_name "
        "FROM numplan n "
        "JOIN routepartition r ON r.pkid = n.fkroutepartition "
        "LEFT JOIN devicenumplanmap m ON m.fknumplan = n.pkid "
        "LEFT JOIN device d ON d.pkid = m.fkdevice "
        "WHERE n.tkpatternusage = '2' "
        f"AND n.dnorpattern IN ({values}) "
        "ORDER BY n.dnorpattern, r.name, d.name"
    )


def classify_directory_numbers(numbers, rows):
    matches = {number: [] for number in numbers}
    if not isinstance(rows, list):
        raise RuntimeError("CUCM Directory Number query returned invalid data.")

    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("CUCM Directory Number query returned an invalid row.")
        pattern = str(row.get("pattern", "") or "").strip()
        if pattern in matches:
            matches[pattern].append(row)

    results = []
    for number in numbers:
        records = matches[number]
        if not records:
            results.append({"pattern": number, "status": "Not Found", "eligible": False, "detail": "No CUCM Directory Number line was found."})
            continue

        partitions = sorted({str(row.get("route_partition", "") or "").strip() for row in records})
        if partitions != [ROUTE_PARTITION]:
            results.append({
                "pattern": number,
                "status": "Blocked",
                "eligible": False,
                "detail": "Found in partition(s) " + ", ".join(partition or "(unknown)" for partition in partitions) + "; only a unique ENT_DEVICE_PT DN can be removed.",
                "partitions": partitions,
            })
            continue

        line_ids = {str(row.get("line_id", "") or "").strip() for row in records}
        if len(line_ids) != 1 or "" in line_ids:
            results.append({"pattern": number, "status": "Blocked", "eligible": False, "detail": "The Directory Number line identity is missing or ambiguous."})
            continue

        active_values = {str(row.get("is_active", "") or "").strip().lower() for row in records}
        if not active_values or not active_values.issubset(INACTIVE_VALUES):
            results.append({"pattern": number, "status": "Blocked", "eligible": False, "detail": "The Directory Number is active or its active state is unknown."})
            continue

        device_ids = {str(row.get("device_id", "") or "").strip() for row in records if str(row.get("device_id", "") or "").strip()}
        device_names = sorted({str(row.get("device_name", "") or "").strip() for row in records if str(row.get("device_name", "") or "").strip()})
        if device_ids or device_names:
            results.append({
                "pattern": number,
                "status": "Blocked",
                "eligible": False,
                "detail": "Assigned to device(s): " + ", ".join(device_names or sorted(device_ids)),
                "devices": device_names or sorted(device_ids),
            })
            continue

        results.append({
            "pattern": number,
            "route_partition": ROUTE_PARTITION,
            "status": "Eligible",
            "eligible": True,
            "detail": "Unique ENT_DEVICE_PT line is inactive and has no device assignments.",
        })

    return results


def results_csv(results):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Directory Number", "Route Partition", "Result", "Action Taken", "Details", "Notification Email"])
    for row in results or []:
        status = str(row.get("status", "") or "")
        action = "Removed from CUCM" if status == "Deleted" else "Not removed"
        email_status = "Sent" if row.get("email_sent") else ("Not sent" if "email_sent" in row else "Not applicable")
        values = [
            row.get("pattern", ""),
            row.get("route_partition", ROUTE_PARTITION),
            status,
            action,
            row.get("detail", ""),
            email_status,
        ]
        safe_values = []
        for value in values:
            text = str(value or "")
            if text.lstrip().startswith(("=", "+", "-", "@")):
                text = "'" + text
            safe_values.append(text)
        writer.writerow(safe_values)
    return output.getvalue().encode("utf-8-sig")