# datadog_interview
Given a traffic.csv containing 45 seconds worth of login activity from a SaaS-based application, surface login anomalies from potential bots/account takeovers

## Install



## Usage


## Features

Real-time Streaming: Treat the traffic.csv file like a real-time event stream. Emulate a stream by reading one line of the csv file per second.
Enrichment: Enrich events with any context you think is valuable.
Statistics: Every 15 seconds, provide a statistical overview of the web traffic (you decide on what stats are important).
Threat Detection: Pick one type of anomalous or suspicious activity and generate an actionable alert when it is detected.
Future Improvements: In your documentation, explain how you would improve on the design of this application.
Deliver your project as a containerized solution implemented in the language of your choice (Go or Python a plus). When submitting your solution, please submit your source code and any instructions needed to run your code using the sample dataset provided. Include any necessary documentation, screenshots, or information we would need to know when reviewing your code.
