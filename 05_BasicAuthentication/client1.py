#!/usr/bin/env python3
import urllib.request

URL = "http://localhost:8000/public"

def main():
    req = urllib.request.Request(URL, method="GET")

    with urllib.request.urlopen(req) as res:
        print("Status:", res.status)
        print("Headers:\n", res.headers)

        body = res.read().decode("utf-8")
        print("Body:\n", body)

if __name__ == "__main__":
    main()