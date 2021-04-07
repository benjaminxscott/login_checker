#!/usr/bin/env python3

import csv
import argparse

from http import HTTPStatus

from user_agents import parse as parse_useragent
import schedule
from loginevents import UserAccount, LoginSource, LoginClient, LoginEvents

def emit_summary(app_logins):
    print('--- STATS ---')
    print(f"Total Successful Logins: {app_logins.total_successful_logins}")
    print(f"Total Failed Logins: {app_logins.total_failed_logins}")
    print(f"Total Suspicious Events: {len(app_logins.suspicious_events)}")

    print('--- EVENTS ---')
    for event in app_logins.suspicious_events.values():
        print(f"Event ID: {event.event_id} (confidence:{event.confidence}) {event.reason} on {event.account.user_id} for {event.login_source.ip_address}")

    print('--- SUSPICIOUS IPS ---')

    for loginsource in app_logins.login_sources.values():
        if loginsource.possible_ato:
            print(f"{loginsource.ip_address} may be conducting ATO, associated with {len(loginsource.successful_logins)} accounts")

        if loginsource.possible_bruting:
            print(f"{loginsource.ip_address} may be brute-forcing, associated with {len(loginsource.successful_logins)} accounts")

    print('--- SUSPICIOUS USERAGENTS ---')
    for loginclient in app_logins.login_clients.values():
        if loginclient.possible_ato:
            print(f"{loginclient.ua_digest} may be conducting ATO, associated with {len(loginclient.successful_logins)} accounts - useragent {loginclient.user_agent}")


def check_useragent(user_agent:str) -> bool:
    ua = parse_useragent(user_agent)
    headless_browsers = ['Headless', 'Phantom', 'Selenium']
    return any([item.lower() in ua.browser.family.lower() for item in headless_browsers]) or 'Other' in ua.os.family

def is_successful_login(status_code:str) -> bool:
    return int(status_code) in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED)

def check_login(account:UserAccount, login_source:LoginSource, login_client:LoginClient, was_successful:bool) -> None:

    if was_successful:
        if login_source.possible_ato:
            app_logins.add_suspicious_event(account, login_source,
                reason = "ATO - known bad srcIP", confidence = 90)

        if check_useragent(user_agent):
            login_source.possible_ato = True
            login_client.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                reason = "ATO - suspicious useragent", confidence = 80)

        if len(login_source.successful_logins) >= 3:
            app_logins.add_suspicious_event(account, login_source,
                reason = "ATO - srcIP associated with three or more accounts", confidence = 60)

        if len(login_source.successful_logins) >= 3:
            app_logins.add_suspicious_event(account, login_source,
                reason = "ATO - srcIP associated with three or more useragents", confidence = 30)
    else:
        if sum(login_source.failed_logins.values()) > 10:
            login_source.possible_bruting = True

        if sum(account.failed_logins.values()) > 3 and login_source.possible_bruting:
            app_logins.add_suspicious_event(account, login_source,
                reason = "Bruting - many failed login attempts", confidence = 50)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Process a given CSV of login events and output anomalies based on heuristics')
    parser.add_argument('infile', nargs='?',type=argparse.FileType('r'),
        help='filename of CSV file to process', default = "traffic.csv")

    args = parser.parse_args()

    app_logins = LoginEvents()

    with args.infile as csvfile:
        reader = csv.DictReader(csvfile)

        # TODO - lauren: several failed logins from same IP , various UAs, then success
            # - keep track of prior failed logins, on success check the failed ones to see if they have suspicious characteristics
            # check at login-source level, "IP associated with many UAs" (low conf since could be library / home)

        for row in reader:
            account = app_logins.get_account(row.get('userid'))
            login_source = app_logins.get_login_source(row.get('ip'))
            user_agent = row.get('useragent')
            login_client = app_logins.get_login_client(user_agent)
            was_successful = is_successful_login(row.get('status_code'))

            if all(account, login_source, user_agent, login_client, was_successful):
                app_logins.add_login(account, login_source, login_client, was_successful)
                check_login(account, login_source, login_client, was_successful)

    emit_summary(app_logins)
    schedule.every(15).seconds.do(emit_summary, app_logins = app_logins)
    # TODO - read a row per second rather than all at once
    while True:
        schedule.run_pending()

# FUTURE: integrate w/ VT to notify on bad IPs https://github.com/VirusTotal/vt-py (env-file for apitoken)
