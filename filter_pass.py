"""
Your password must be at least 8 characters and at most 128 characters.
Your password must contain characters from three of the following categories – English uppercase letters, English lowercase letters, numbers (0-9), and non-alphanumeric characters (!, $, #, %, etc.).
Your password cannot contain all or part of the login name. Part of a login name is defined as three or more consecutive alphanumeric characters.
"""
import argparse
import re

MIN_LENGTH = 8

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Filter out a word list to meet password complexity requirements."
    )
    parser.add_argument(
        "lists", metavar="wordlist", type=str, nargs="+", help="word list file(s)"
    )

    args = parser.parse_args()

    for f in args.lists:
        with open(f) as wordlist:
            for line in wordlist:
                pw = line.strip()
                if len(pw) < MIN_LENGTH:  # Faster than doing regex
                    continue

                pattern = "^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"
                result = re.findall(pattern, pw)
                if result:
                    print(pw)

