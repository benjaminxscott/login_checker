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

The script will infinitely loop, emitting a summary every 15 seconds

Input `Ctrl+C` or the equivalent escape code to stop the container process once you're finished

## Features

Real-time Streaming: Treat the traffic.csv file like a real-time event stream. Emulate a stream by reading one line of the csv file per second.
Enrichment: Enrich events with any context you think is valuable.
Statistics: Every 15 seconds, provide a statistical overview of the web traffic (you decide on what stats are important).
Threat Detection: Pick one type of anomalous or suspicious activity and generate an actionable alert when it is detected.
Future Improvements: In your documentation, explain how you would improve on the design of this application.
Deliver your project as a containerized solution implemented in the language of your choice (Go or Python a plus). When submitting your solution, please submit your source code and any instructions needed to run your code using the sample dataset provided. Include any necessary documentation, screenshots, or information we would need to know when reviewing your code.

## Maintaining

Dependencies are pinned using [pip-compile](https://github.com/jazzband/pip-tools#example-usage-for-pip-compile)

If you need to update dependency versions, modify `requirements.in` and re-run `pip-compile`:

> pip-compile --generate-hashes requirements.in
