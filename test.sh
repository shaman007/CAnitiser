#!/bin/bash

python ca-nitiser.py > images.json
python ca-analyse.py --images images.json --policy policy.json > report.json
python ca-report-html.py --report report.json -o report.html