"""Exercise the running localhost server's actual HTTP input boundaries."""

import argparse
import http.client
import json
from pathlib import Path


def request(method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", 5000, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(16384) if response.status < 400 else b""
        return response.status, data
    finally:
        connection.close()


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    if args.output.exists():
        cli.error("Output exists")
    cases = {}
    status, data = request(
        "POST",
        "/api/analyze",
        json.dumps(dict(url="example.com")),
        {"Content-Type": "application/json"},
    )
    cases["valid_passive_json"] = dict(
        status=status, passed=status == 200 and json.loads(data)["scope"]["active"] is False
    )
    for name, body, headers, expected in (
        ("oversized_body", b"x" * 8192, {"Content-Type": "application/json"}, 413),
        ("oversized_header", b"", {"X-Long": "x" * 17000}, 431),
        (
            "foreign_origin",
            b'{"url":"example.com"}',
            {"Content-Type": "application/json", "Origin": "https://other.example"},
            403,
        ),
        (
            "rebinding_host",
            b'{"url":"example.com"}',
            {"Content-Type": "application/json", "Host": "other.example"},
            400,
        ),
    ):
        status, _data = request("POST", "/api/analyze", body, headers)
        cases[name] = dict(status=status, expected=expected, passed=status == expected)
    result = dict(
        scope="Running Waitress on localhost; all analysis requests passive, no inspected-site egress",
        cases=cases,
        passed=all(x["passed"] for x in cases.values()),
    )
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
