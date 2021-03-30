#!/usr/bin/env python3

import csv
import argparse
import typing

from time import sleep
from collections import Counter
from http import HTTPStatus
from user_agents import parse

def is_bot(user_agent):
    headless_browsers = ['Headless', 'Phantom', 'Selenium']
    return any([item.lower() in user_agent.browser.family.lower() for item in headless_browsers]) or 'Other' in user_agent.os.family

def successful_login(status_code):
    return int(status_code) in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED)

class UserAccount:
    def __init__(self, user_id:str):
        self.user_id = user_id
        self.failed_logins = Counter()
        self.possible_ato = False
        self.possible_bruting = False
        self.possible_bruting = False

# TODO - use this object when using plain IPs
class LoginIP:
    def __init__(self, ip_address:str):
        self.ip_address = ip_address
        self.failed_logins = Counter()
        self.successful_logins = set()
        self.disposition = None
        self.possible_bruting = False
        self.possible_ato = False

class LoginEvents:
    def __init__(self):
        self.user_accounts = {}
        self.login_ips = {}

    def get_account(self, user_id:str) -> UserAccount:
        account = self.user_accounts.get(user_id)
        if not account:
            account = UserAccount(user_id)
            print(account)
            self.user_accounts[user_id] = account
        return account

    def get_ip(self, ip_address:str) -> LoginIP:
        login_ip = self.login_ips.get(ip_address)
        if not login_ip:
            login_ip = LoginIP(ip_address)
            self.login_ips[ip_address] = login_ip
        return login_ip

    def add_failed_login(self, account:UserAccount, login_ip:LoginIP):
        self.user_accounts.get(account.user_id).failed_logins.update({login_ip})
        self.login_ips.get(login_ip.ip_address).failed_logins.update({account})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Process a given CSV of login events and output anomalies based on heuristics')
    parser.add_argument('infile', nargs='?',type=argparse.FileType('r'),
        help='filename of CSV file to process', default = "traffic.csv")

    # FUTURE - flags for type of events to emit, default all

    args = parser.parse_args()

    loginevents = LoginEvents()
    unique_logins = {}

    with args.infile as csvfile:
        reader = csv.DictReader(csvfile)
        # TODO - logins from many IPs to a single user, eventually getting 20x (ATO)
        # TODO - logins from same IP or UA to many accounts

        for row in reader:
            account = loginevents.get_account(row.get('userid'))
            login_ip = loginevents.get_ip(row.get('ip'))

            if successful_login(row.get('status_code')):
                login_ip.successful_logins.add(account.user_id)
                if is_bot(parse(row.get('useragent'))):
                    account.possible_ato = True
                    login_ip.possible_ato = True
            else:
                loginevents.add_failed_login(account, login_ip)
                if sum(account.failed_logins.values()) > 3:
                    account.possible_bruting = True
                if sum(login_ip.failed_logins.values()) > 3:
                    login_ip.possible_bruting = True

    # emit summary
    for account in loginevents.user_accounts.values():
        if account.possible_ato:
            print (f"POSSIBLE_ATO for {account.user_id}")
        if account.possible_bruting:
            print (f"POSSIBLE_BRUTING for {account.user_id} with {sum(account.failed_logins.values())} attempts from {len(account.failed_logins)} distinct IPs")

    for login_ip in loginevents.login_ips.values():
        print(sum(login_ip.failed_logins.values()))
        if login_ip.possible_ato:
            print (f"POSSIBLE_ATO for {login_ip.ip_address} with {len(login_ip.successful_logins)} affected accounts")
        if login_ip.possible_bruting:
            print (f"POSSIBLE_BRUTING for {login_ip.ip_address} with {sum(login_ip.failed_logins.values())} attempts to {len(login_ip.failed_logins)} distinct accounts")

# FUTURE: integrate w/ VT to notify on bad IPs https://github.com/VirusTotal/vt-py (env-file for apitoken)
