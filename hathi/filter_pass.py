"""
Your password must be at least 8 characters and at most 128 characters.
Your password must contain characters from three of the following categories – English uppercase letters, English lowercase letters, numbers (0-9), and non-alphanumeric characters (!, $, #, %, etc.).
Your password cannot contain all or part of the login name. Part of a login name is defined as three or more consecutive alphanumeric characters.
"""
from typing import List
import re

MIN_LENGTH = 8

def filter_passwords(wordlists: List[str]):
    for f in wordlists:
        with open(f) as wordlist:
            for line in wordlist:
                pw = line.strip()
                if len(pw) < MIN_LENGTH:  # Faster than doing regex
                    continue

                pattern = "^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"
                result = re.findall(pattern, pw)
                if result:
                    print(pw)

