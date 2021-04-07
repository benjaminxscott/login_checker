# datadog_interview
Given a traffic.csv containing 45 seconds worth of login activity from a SaaS-based application, surface login anomalies from potential bots/account takeovers

## Possible Enhancements
- Integrate w/ VT to provide context on source IPs https://github.com/VirusTotal/vt-py (env-file for apitoken)
- Use a real database for LoginEvents, with foreign keys into tables for clients and user accounts
- Connect to ticketing system / mitigation automation (i.e. requiring captcha on bruting, forcing password reset on ATO)
- Setup interactive web application with API


## Install

> docker build -t login_checker .

## Usage

Provide a file in CSV format named `traffic.csv` with header fields for
- userid
- event_type
- status_code
- ip
- useragent

Run the script to see a summary of login anomalies
> docker run login_checker:latest

In order to read each line once per second, emitting a summary every 15 seconds

> docker run login_checker:latest --daemon --stream

Input `Ctrl+C` or the equivalent escape code to stop the container process once you're finished

## Maintaining

Dependencies are pinned using [pip-compile](https://github.com/jazzband/pip-tools#example-usage-for-pip-compile)

If you need to update dependency versions, modify `requirements.in` and re-run `pip-compile`:

> pip-compile --generate-hashes requirements.in
