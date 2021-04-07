"""
Helper library for login checker
"""

import hashlib
from collections import Counter

import shortuuid

class UserAccount:
    def __init__(self, user_id:str):
        self.user_id = user_id
        self.failed_logins = Counter()

class UserAgent:
    def __init__(self, ua_string:str):
        self.ua_string = ua_string
        self.ua_digest = hashlib.sha1(bytes(ua_string, 'utf-8')).hexdigest()
        self.failed_logins = Counter()
        self.related_login_sources = set()
        self.successful_logins = set()
        self.possible_ato = False
        self.possible_bruting = False

class LoginSource:
    def __init__(self, ip_address:str):
        self.ip_address = ip_address
        self.failed_logins = Counter()
        self.successful_logins = set()
        self.disposition = None
        self.possible_bruting = False
        self.possible_ato = False


class Alert:
    def __init__(self, alert_type, severity = 0):
        self.alert_type = alert_type
        self.severity = severity

    def __repr__(self):
        return str(self.alert_type)

class SuspiciousEvent:
    def __init__(self, account:UserAccount, login_source:LoginSource, alert_type:Alert, description:str = 'description not provided', confidence:int = 0):
        self.event_id = shortuuid.uuid()
        self.alert_type = alert_type
        self.description = description
        self.confidence = confidence
        self.account = account
        self.login_source = login_source

class LoginEvents:
    def __init__(self):
        self.total_successful_logins = 0
        self.total_failed_logins = 0
        self.user_accounts = {}
        self.login_sources = {}
        self.login_clients = {}
        self.suspicious_events = {}

    def get_account(self, user_id:str) -> UserAccount:
        account = self.user_accounts.get(user_id)
        if not account:
            account = UserAccount(user_id)
            self.user_accounts[user_id] = account
        return account

    def get_login_source(self, ip_address:str) -> LoginSource:
        login_source = self.login_sources.get(ip_address)
        if not login_source:
            login_source = LoginSource(ip_address)
            self.login_sources[ip_address] = login_source
        return login_source

    def get_login_client(self, ua_string:str) -> UserAgent:
        ua_digest = hashlib.sha1(bytes(ua_string, 'utf-8')).hexdigest()
        login_client = self.login_clients.get(ua_digest)
        if not login_client:
            login_client = UserAgent(ua_string)
            self.login_clients[ua_digest] = login_client
        return login_client

    def add_login(self, account:UserAccount, login_source:LoginSource, login_client:UserAgent, was_successful:bool = False) -> None:
        if was_successful:
            self.total_successful_logins += 1
            self.login_sources.get(login_source.ip_address).successful_logins.add(account)
            self.login_clients.get(login_client.ua_digest).successful_logins.add(account)
            self.login_clients.get(login_client.ua_digest).related_login_sources.add(login_source)
        else:
            self.total_failed_logins += 1
            self.user_accounts.get(account.user_id).failed_logins.update({login_source})
            self.login_sources.get(login_source.ip_address).failed_logins.update({account})
            self.login_clients.get(login_client.ua_digest).failed_logins.update({account})

    def add_suspicious_event(self, account:UserAccount, login_source:LoginSource, alert_type:Alert, description:str = None, confidence:str = None) -> None:
        event = SuspiciousEvent(account, login_source, alert_type, description, confidence)
        self.suspicious_events.update({event.event_id: event})
