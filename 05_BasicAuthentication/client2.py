#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import base64

URL = "http://localhost:8000/private"

USERNAME = "user"
PASSWORD = "pass"

def main():
    credentials = f"{USERNAME}:{PASSWORD}"

    # Base64エンコード
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

    print("username          : ", USERNAME)
    print("password          : ", PASSWORD)
    print("username:password : ", credentials)
    print("base64 encoded    : ", encoded)
    # Authorizationヘッダの完全形
    print("Authorization     : ", f"Basic {encoded}")


    # 通常のrequestsの認証
    res = requests.get(URL, auth=HTTPBasicAuth(USERNAME, PASSWORD))

    print("Status:", res.status_code)
    print("Headers:\n", res.headers)
    print("Body:\n", res.text)

if __name__ == "__main__":
    main()