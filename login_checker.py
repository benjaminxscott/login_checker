#!/usr/bin/env python3

import csv
import argparse

from http import HTTPStatus

from user_agents import parse as parse_useragent
import schedule
from loginevents import UserAccount, LoginSource, UserAgent, LoginEvents, Alert

def emit_summary(app_logins):
    print('--- STATS ---')
    print(f"Total Successful Logins: {app_logins.total_successful_logins}")
    print(f"Total Failed Logins: {app_logins.total_failed_logins}")
    print(f"Total Suspicious Events: {len(app_logins.suspicious_events)}")

    print('--- EVENTS ---')
    for event in app_logins.suspicious_events.values():
        print(f"Event ID: {event.event_id} [severity:{event.alert_type.severity}](confidence:{event.confidence}) {event.alert_type} - {event.description} on {event.account.user_id} for {event.login_source.ip_address}")

    print('--- SUSPICIOUS IPS ---')

    for loginsource in app_logins.login_sources.values():
        if loginsource.possible_ato:
            print(f"{loginsource.ip_address} may be conducting ATO, logged into {len(loginsource.successful_logins)} accounts")

        if loginsource.possible_bruting:
            print(f"{loginsource.ip_address} may be brute-forcing, logged into {len(loginsource.successful_logins)} accounts")

    # TODO - emit bruting UAs,
    print('--- SUSPICIOUS USERAGENTS ---')
    for useragent in app_logins.login_clients.values():
        if useragent.possible_ato:
            print(f"{useragent.ua_digest} may be conducting ATO, logged into {len(useragent.successful_logins)} accounts - useragent {useragent.ua_string}")
        if useragent.possible_bruting:
            print(f"{useragent.ua_digest} may be brute-forcing, logged into {len(useragent.successful_logins)} accounts - useragent {useragent.ua_string}")


def check_useragent(ua_string:str) -> bool:
    ua = parse_useragent(ua_string)
    headless_browsers = ['Headless', 'Phantom', 'Selenium']
    return any([item.lower() in ua.browser.family.lower() for item in headless_browsers]) or 'Other' in ua.os.family

def is_successful_login(status_code:str) -> bool:
    return int(status_code) in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED)

def check_login(account:UserAccount, login_source:LoginSource, login_client:UserAgent, was_successful:bool) -> None:
    if was_successful:
        if login_source.possible_ato or login_client.possible_ato:
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 80),
                description = "known bad srcIP", confidence = 90)

        if check_useragent(ua_string) or login_client.possible_ato:
            login_source.possible_ato = True
            login_client.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 80),
                description = "suspicious useragent", confidence = 80)

        if len(login_source.successful_logins) >= 3:
            login_source.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 70),
                description = "srcIP logged into three or more accounts", confidence = 60)

        # TODO - handle useragents > 3 for a given IP
        if len(login_source.successful_logins) >= 3:
            login_source.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 50),
                description = "srcIP logged into three or more useragents", confidence = 30)
    else:
        print(f"{account.user_id}: {account.failed_logins.values()}")
        if sum(account.failed_logins.values()) > 5:
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'Bruting', severity = 10),
                description = f"Account had more than five failed login attempts", confidence = 50)

        if sum(login_source.failed_logins.values()) > 5:
            login_source.possible_bruting = True

        if sum(login_client.failed_logins.values()) > 5:
            login_client.possible_bruting = True

# TODO - lauren: several failed logins from same IP , various UAs, then success
    # - keep track of prior failed logins, on success check the failed ones to see if they have suspicious characteristics
    # check at login-source level, "IP logged into many UAs" (low conf since could be library / home)

        if sum(login_source.failed_logins.values()) > 10:
            login_source.possible_bruting = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'Bruting', severity = 30),
                description = "many failed login attempts", confidence = 50)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Process a given CSV of login events and output anomalies based on heuristics')
    parser.add_argument('infile', nargs='?',type=argparse.FileType('r'),
        help='filename of CSV file to process', default = "traffic.csv")

    args = parser.parse_args()

    app_logins = LoginEvents()

    with args.infile as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            account = app_logins.get_account(row.get('userid'))
            login_source = app_logins.get_login_source(row.get('ip'))
            ua_string = row.get('useragent')
            login_client = app_logins.get_login_client(ua_string)

            if all([account, login_source, ua_string, login_client]):
                was_successful = is_successful_login(row.get('status_code'))
                app_logins.add_login(account, login_source, login_client, was_successful)
                check_login(account, login_source, login_client, was_successful)

    emit_summary(app_logins)
    schedule.every(15).seconds.do(emit_summary, app_logins = app_logins)
    # TODO - read a row per second rather than all at once
    while True:
        schedule.run_pending()
