import argparse
import csv
import json
import sys
from getpass import getpass

try:
    # When running from toolkit directory.
    from translation_pattern_lookup import lookup_translation_patterns
except ImportError:
    # When running from repository root.
    from toolkit.translation_pattern_lookup import lookup_translation_patterns


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "pattern",
            "description",
            "route_partition",
            "called_party_transform_mask",
        ])
        for item in rows:
            writer.writerow([
                item.get("pattern", ""),
                item.get("description", ""),
                item.get("route_partition", ""),
                item.get("called_party_transform_mask", ""),
            ])


def main():
    parser = argparse.ArgumentParser(
        description="Extract translation pattern details from CUCM.",
    )
    parser.add_argument("--host", required=True, help="CUCM host (example: lascucmpp01.ahs.int)")
    parser.add_argument("--user", required=True, help="CUCM username")
    parser.add_argument("--password", help="CUCM password (omit to be prompted)")
    parser.add_argument(
        "--pattern",
        default="3148984689",
        help="Pattern contains query (default: 3148984689)",
    )
    parser.add_argument(
        "--first-only",
        action="store_true",
        help="Return only the first result",
    )
    parser.add_argument(
        "--csv-out",
        help="Optional CSV output path",
    )

    args = parser.parse_args()
    password = args.password or getpass("CUCM password: ")

    try:
        results = lookup_translation_patterns(args.host, args.user, password, args.pattern)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not results:
        print("No translation patterns found.")
        return 0

    output_rows = results[:1] if args.first_only else results

    print(json.dumps(output_rows, indent=2))

    if args.csv_out:
        _write_csv(args.csv_out, output_rows)
        print(f"Wrote CSV: {args.csv_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
