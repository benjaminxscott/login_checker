#!/usr/bin/env python3

import csv
import argparse
from time import sleep

from http import HTTPStatus

from user_agents import parse as parse_useragent
import schedule
from loginevents import UserAccount, LoginSource, UserAgent, LoginEvents, Alert

# TODO - doc infile flag
# - setup docker volume for folder so it can be loaded
# - add to readme --mount source="$(pwd)"/input, target=/usr/src/app/input,readonly

def emit_summary(app_logins):
    print('=' * 20)
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

    print('--- SUSPICIOUS USERAGENTS ---')
    for useragent in app_logins.useragents.values():
        if useragent.possible_ato:
            print(f"Useragent with digest {useragent.ua_digest} may be conducting ATO, logged into {len(useragent.successful_logins)} accounts - useragent string '{useragent.ua_string}'")
        if useragent.possible_bruting:
            print(f"Useragent with digest {useragent.ua_digest} may be brute-forcing, logged into {len(useragent.successful_logins)} accounts - useragent string '{useragent.ua_string}'")


def check_useragent(ua_string:str) -> bool:
    ua = parse_useragent(ua_string)
    headless_browsers = ['Headless', 'Phantom', 'Selenium']
    return any([item.lower() in ua.browser.family.lower() for item in headless_browsers]) or 'Other' in ua.os.family

def is_successful_login(status_code:str) -> bool:
    return int(status_code) in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED)

def check_login(account:UserAccount, login_source:LoginSource, useragent:UserAgent, was_successful:bool) -> None:
    if was_successful:
        if account.previous_login_failures >= 2:
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 80),
                description = "successful login after three previous failed logins", confidence = 90)
            account.previous_login_failures = 0

        if login_source.possible_ato or useragent.possible_ato:
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 80),
                description = "known bad srcIP", confidence = 90)

        if check_useragent(useragent.ua_string):
            login_source.possible_ato = True
            useragent.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 80),
                description = "suspicious useragent", confidence = 80)

        if len(login_source.successful_logins) >= 3:
            login_source.possible_ato = True
            useragent.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 70),
                description = "srcIP logged into three or more accounts", confidence = 60)

        if len(login_source.associated_useragents) >= 3:
            login_source.possible_ato = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'ATO', severity = 50),
                description = "srcIP associated with three or more useragents", confidence = 30)
    else:
        if sum(login_source.failed_logins.values()) > 5:
            login_source.possible_bruting = True

        if sum(useragent.failed_logins.values()) > 5:
            useragent.possible_bruting = True

        # we only generate discrete alerts for particularly high numbers of failed logins
        if sum(login_source.failed_logins.values()) > 10:
            login_source.possible_bruting = True
            app_logins.add_suspicious_event(account, login_source,
                alert_type = Alert(alert_type = 'Bruting', severity = 30),
                description = "many failed login attempts", confidence = 50)

def test_detection_logic():
    account = UserAccount('ben')
    login_source = LoginSource('8.8.4.4')
    useragent = UserAgent('curl')

    # TEST - test "two failures then success"
    app_logins.add_login(account, login_source, useragent, False)
    app_logins.add_login(account, login_source, useragent, False)
    app_logins.add_login(account, login_source, useragent, True)
    check_login(account, login_source, useragent, True)
    try:
        assert len(app_logins.suspicious_events) > 0
    except AssertionError:
        print("failed test of \"two failures then success\"")
        exit(1)

    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Process a given CSV of login events and output anomalies based on heuristics')
    parser.add_argument('infile', nargs='?',type=argparse.FileType('r'),
        help='filename of CSV file to process', default = "traffic.csv")
    parser.add_argument('--stream', '-s', action = 'store_true', help='Delay for 1s between reading each line of input file')
    parser.add_argument('--daemon', '-d', action = 'store_true', help='Output summary every 15s, instead of right away')
    parser.add_argument('--test', action = 'store_true', help='Test that detections work properly')

    # FUTURE - how about reading from file after it's appended to
    args = parser.parse_args()
    app_logins = LoginEvents()

    if args.test:
        test_detection_logic()
        exit(0)

    if args.daemon:
        schedule.every(15).seconds.do(emit_summary, app_logins = app_logins)

    # ingest lines from infile
    with args.infile as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            schedule.run_pending()
            account = app_logins.get_account(row.get('userid'))
            login_source = app_logins.get_login_source(row.get('ip'))
            ua_string = row.get('useragent')
            useragent = app_logins.get_useragent(ua_string)

            if all([account, login_source, ua_string, useragent]):
                was_successful = is_successful_login(row.get('status_code'))
                app_logins.add_login(account, login_source, useragent, was_successful)
                check_login(account, login_source, useragent, was_successful)

            if args.stream:
                sleep(1)

    if not args.daemon:
        emit_summary(app_logins)
