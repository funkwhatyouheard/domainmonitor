# domainmonitor
Uses dnstwist to monitor domains/look-alikes and their changes

Installation:
$ sudo apt install python3-dnspython python3-tld python3-geoip python3-whois \
python3-requests python3-ssdeep

$ pip install -r requirements.txt

Once base packages are installed, add domains you want to monitor to a new-line separated file in the same dir (domains.txt) and run.
$ python3 ./domainmonitor.py

Each run will compare against previous results and output to domainData.json file.
