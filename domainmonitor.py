#!/usr/bin/python3

import dnstwist
import whois
import sys
import signal
import time
import argparse
import warnings
from os import path
import json
import queue

global args

def standardize_json(domains=[],
fields=['fuzzer','domain-name','dns-a','dns-aaaa','dns-mx','dns-ns','geoip-country','whois-created','ssdeep-score']):
	domains = list(domains)
	for domain in domains:
		for field in fields:
			if field in domain and field == 'domain-name':
				domain[field] = domain[field].encode('idna').decode()
			elif field not in domain:
				domain[field] = [] if field.startswith('dns') else ""
	return domains

# tweaked to output uniformly
def create_csv(domains=[],fields=['fuzzer','domain-name','dns-a','dns-aaaa','dns-mx','dns-ns','geoip-country','whois-created','ssdeep-score']):
	csv = [",".join(fields)]
	for domain in domains:
		csv.append(','.join([domain.get('fuzzer',""), 
			domain.get('domain-name',"").encode('idna').decode(),
			';'.join(domain.get('dns-a', [])),
			';'.join(domain.get('dns-aaaa', [])),
			';'.join(domain.get('dns-mx', [])),
			';'.join(domain.get('dns-ns', [])),
			domain.get('geoip-country',""), 
			domain.get('whois-created',""),
			str(domain.get('ssdeep-score', ""))]))
	return '\n'.join(csv)

def _exit(code):
		print(dnstwist.FG_RST + dnstwist.ST_RST, end='')
		sys.exit(code)

def p_cli(text):
		if args.format == 'cli': print(text, end='', flush=True)

def p_err(text):
	print(text, file=sys.stderr, flush=True)

def signal_handler(signal, frame):
	print('\nStopping threads... ', file=sys.stderr, end='', flush=True)
	for worker in threads:
		worker.stop()
		worker.join()
	print('Done', file=sys.stderr)
	_exit(0)

def write_log(message,cli=False):
	if cli:
		p_cli(message)
	else:
		print(message)

def write_warning(warning,cli=False):
	if cli:
		p_cli(warning)
	else:
		warnings.warn(warning)

def write_error(error,cli=False):
	if cli:
		p_err(error)
		_exit(-1)
	else:
		raise error

#TODO: rework this
def dnstwister(domain,all=False,banners=False,dictionary=None,geoip=False,mxcheck=False,output=None,registered=False,ssdeep=False,ssdeep_url=None,threadcount=dnstwist.THREAD_COUNT_DEFAULT,whois=False,tld=None,nameservers=None,port=53,useragent=None,cli=False,format="cli"):
	# When args are parsed in from the cli, they create a Namespace object
	# this object is essentially just strings that are parsed out to objects at time of use
	# most are bool or string, so nbd, but namespaces can take a list... kind of
	# it's expecting a comma separated list, not an actual list() object
	#
	# uses the same params as main() with the exception of format which is assumed to be json
	global args
	global threads

	if isinstance(nameservers, list):
		nameservers = ",".join(nameservers)
	args = argparse.Namespace(**locals())
	threads = []
	nameservers = []
	dictionary = []
	tld = []

	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)

	if args.threadcount < 1:
		args.threadcount = dnstwist.THREAD_COUNT_DEFAULT

	if args.nameservers:
		nameservers = args.nameservers.split(',')
		for r in nameservers:
			if len(r.split('.')) != 4:
				write_error(ValueError('Error: Invalid DNS nameserver',cli))

	if args.dictionary:
		if not path.exists(args.dictionary):
			write_error(FileNotFoundError('Error: Dictionary file not found: %s\n' % args.dictionary),cli)
		with open(args.dictionary) as f:
			dictionary = set(f.read().splitlines())
			dictionary = [x for x in dictionary if x.isalnum()]

	if args.tld:
		if not path.exists(args.tld):
			write_error(FileNotFoundError('Error: Dictionary file not found: %s\n' % args.tld),cli)
		with open(args.tld) as f:
			tld = set(f.read().splitlines())
			tld = [x for x in tld if x.isalpha()]

	if args.output:
		try:
			sys.stdout = open(args.output, 'x')
		except FileExistsError:
			write_error(FileExistsError('File already exists: %s' % args.output),cli)
			raise
		except FileNotFoundError:
			write_error(FileNotFoundError('No such file or directory: %s' % args.output),cli)
			raise
		except PermissionError:
			write_error(PermissionError('Permission denied: %s' % args.output),cli)
			raise

	if args.ssdeep_url:
		try:
			ssdeep_url = dnstwist.UrlParser(args.ssdeep_url)
		except ValueError:
			write_error(ValueError('Invalid domain name: ' + args.ssdeep_url),cli)
	
	try:
		url = dnstwist.UrlParser(args.domain)
	except ValueError as err:
		write_error(ValueError('Error: %s\n' % err),cli)
		raise

	fuzz = dnstwist.DomainFuzz(url.domain, dictionary=dictionary, tld_dictionary=tld)
	fuzz.generate()
	domains = fuzz.domains

	if args.format == 'list' and cli:
		print(dnstwist.create_list(domains))
		_exit(0)

	if not dnstwist.MODULE_DNSPYTHON:
		write_warning('Notice: Missing module DNSPython (DNS features limited)\n',cli)
	if not dnstwist.MODULE_GEOIP and args.geoip:
		write_warning('Notice: Missing module GeoIP (geographical location not available)\n',cli)		
	if not dnstwist.MODULE_WHOIS and args.whois:
		write_warning('Notice: Missing module whois (WHOIS database not accessible)\n',cli)
	if not dnstwist.MODULE_SSDEEP and args.ssdeep:
		write_warning('Notice: Missing module ssdeep (fuzzy hashes not available)\n',cli)
	if not dnstwist.MODULE_REQUESTS and args.ssdeep:
		write_warning('Notice: Missing module Requests (webpage downloads not possible)\n',cli)

	if cli:
			p_cli(dnstwist.FG_RND + dnstwist.ST_BRI +
'''     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}
''' % dnstwist.__version__ + dnstwist.FG_RST + dnstwist.ST_RST)

	ssdeep_init = str()
	ssdeep_effective_url = str()
	if args.ssdeep and dnstwist.MODULE_SSDEEP and dnstwist.MODULE_REQUESTS:
		request_url = ssdeep_url.full_uri() if ssdeep_url else url.full_uri()
		write_log('Fetching content from: ' + request_url + ' ... ',cli)
		try:
			req = dnstwist.requests.get(request_url, timeout=dnstwist.REQUEST_TIMEOUT_HTTP, headers={'User-Agent': args.useragent})
		except dnstwist.requests.exceptions.ConnectionError:
			write_log('Connection error\n')
			args.ssdeep = False
			pass
		except dnstwist.requests.exceptions.HTTPError:
			write_log('Invalid HTTP response\n')
			args.ssdeep = False
			pass
		except dnstwist.requests.exceptions.Timeout:
			write_log('Timeout (%d seconds)\n' % dnstwist.REQUEST_TIMEOUT_HTTP)
			args.ssdeep = False
			pass
		except Exception:
			write_log('Failed!\n')
			args.ssdeep = False
			pass
		else:
			if len(req.history) > 1:
				p_cli('➔ %s ' % req.url.split('?')[0])
			write_log('%d %s (%.1f Kbytes)\n' % (req.status_code, req.reason, float(len(req.text))/1000),cli)
			if req.status_code / 100 == 2:
				ssdeep_init = dnstwist.ssdeep.hash(''.join(req.text.split()).lower())
				ssdeep_effective_url = req.url.split('?')[0]
			else:
				args.ssdeep = False

	write_log('Processing %d premutations ' % len(domains))

	jobs = queue.Queue()

	for i in range(len(domains)):
		jobs.put(domains[i])

	for i in range(args.threadcount):
		worker = dnstwist.DomainThread(jobs)
		worker.setDaemon(True)

		worker.uri_scheme = url.scheme
		worker.uri_path = url.path
		worker.uri_query = url.query

		worker.domain_init = url.domain

		if dnstwist.MODULE_DNSPYTHON:
			worker.option_extdns = True
		if dnstwist.MODULE_GEOIP and args.geoip:
			worker.option_geoip = True
		if args.banners:
			worker.option_banners = True
		if args.ssdeep and dnstwist.MODULE_REQUESTS and dnstwist.MODULE_SSDEEP and 'ssdeep_init' in locals():
			worker.option_ssdeep = True
			worker.ssdeep_init = ssdeep_init
			worker.ssdeep_effective_url = ssdeep_effective_url
		if args.mxcheck:
			worker.option_mxcheck = True
		if args.nameservers:
			worker.nameservers = nameservers
		worker.useragent = args.useragent

		worker.start()
		threads.append(worker)

	qperc = 0
	while not jobs.empty():
		if cli:
			p_cli('.')
		qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
		if qcurr - 20 >= qperc:
			qperc = qcurr
			write_log('%u%%' % qperc,cli)
		time.sleep(1.0)

	for worker in threads:
		worker.stop()
		worker.join()

	hits_total = sum(('dns-ns' in d and len(d['dns-ns']) > 1) or ('dns-a' in d and len(d['dns-a']) > 1) for d in domains)
	hits_percent = 100 * hits_total / len(domains)
	write_log(' %d hits (%d%%)\n\n' % (hits_total, hits_percent),cli)

	if args.registered:
		domains[:] = [d for d in domains if 'dns-a' in d and len(d['dns-a']) > 0]

	if dnstwist.MODULE_WHOIS and args.whois and not fuzz.subdomain:
		write_log('Querying WHOIS servers ',cli)
		for domain in domains:
			domain['whois-created'] = str()
			domain['whois-updated'] = str()
			if len(domain) > 2:
				if cli:
					p_cli('·')
				try:
					whoisq = whois.query(domain['domain-name'].encode('idna').decode())
					if whoisq:
						domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
						domain['whois-updated'] = str(whoisq.last_updated).split(' ')[0]
				except Exception:
					pass
		write_log(' Done\n',cli)

	write_log('\n',cli)

	if not args.all:
		for i in range(len(domains)):
			for k in ['dns-ns', 'dns-a', 'dns-aaaa', 'dns-mx']:
				if k in domains[i]:
					domains[i][k] = domains[i][k][:1]

	if domains:
		if not cli:
			return standardize_json(domains)
		else:
			if args.format == 'csv':
				print(create_csv(domains))
			elif args.format == 'json':
				print(dnstwist.create_json(domains))
			else:
				print(dnstwist.create_cli(domains))
			_exit(0)

def compare_domains(old,new,keys):
	# check key existence; if none, fail
	# if new value != new value add a message to updates list
	updates = list()
	if old != new:
		for key in keys:
			if key not in old or key not in new:
				raise KeyError("Missing key in dictionary:",key)
			if old[key] != new[key]:
				updates.append(f"{key} changed from {old[key]}")
	return updates

def set_diff(old,new):
	additions = list(new.difference(old))
	additions.sort()
	subtractions = list(old.difference(new))
	subtractions.sort()
	intersection = list(new.intersection(old))
	intersection.sort()
	return additions, subtractions, intersection

def compareData(old_domains,new_domains,comparison_keys):
	# first handle the origin domains that have been added/removed
	report_list = dict()
	new_origins = set([d for d in new_domains.keys()])
	old_origins = set([d for d in old_domains.keys()])
	origin_additions, origin_subtractions, origin_intersection = set_diff(old_origins,new_origins)
	# add additions
	for d in origin_additions:
		report_list[d] = list(new_domains[d])
	# mark as additions
	for origin_domain in origin_additions:
		for fuzzed in new_domains[origin_domain]:
			fuzzed['action'] = 'added'
	# add subtractions
	for d in origin_subtractions:
		report_list[d] = list(old_domains[d])
	# mark as removals
	for origin_domain in origin_subtractions:
		for fuzzed in old_domains[origin_domain]:
			fuzzed['action'] = 'removed'
	
	# next, handle the intersection
	for origin_domain in origin_intersection:
		# these have been presorted, and sets are unordered so have to create arrays to be able to match index
		# correctly for the dictionary objects that represent the fuzzed domains
		new_domain_names = [d['domain-name'] for d in new_domains[origin_domain]]
		old_domain_names = [d['domain-name'] for d in old_domains[origin_domain]]
		new_fuzz = set(new_domain_names)
		old_fuzz = set(old_domain_names)
		fuzz_additions, fuzz_subtractions, fuzz_intersection = set_diff(old_fuzz,new_fuzz)
		report_list[origin_domain] = list()
		prev_index_new = 0
		prev_index_old = 0
		prev_i_new_intersect = 0
		prev_i_old_intersect = 0

		# additions
		for d in fuzz_additions:
			# search and add to report_list
			index = new_domain_names.index(d,prev_index_new)
			prev_index_new = index
			fuzzed = dict(new_domains[origin_domain][index])
			fuzzed['action'] = 'added'
			report_list[origin_domain].append(fuzzed)

		# subtractions
		for d in fuzz_subtractions:
			# search and add to report_list
			index = old_domain_names.index(d,prev_index_old)
			prev_index_old = index
			fuzzed = dict(old_domains[origin_domain][index])
			fuzzed['action'] = 'removed'
			report_list[origin_domain].append(fuzzed)

		# handle intersection
		for d in fuzz_intersection:
			# get old dict
			old_index = old_domain_names.index(d,prev_i_old_intersect)
			prev_i_old_intersect = old_index
			old_fuzzed = dict(old_domains[origin_domain][old_index])
			# get new dict
			new_index = new_domain_names.index(d,prev_i_new_intersect)
			prev_i_new_intersect = new_index
			new_fuzzed = dict(new_domains[origin_domain][new_index])
			# compare
			updates = compare_domains(old_fuzzed,new_fuzzed,comparison_keys)
			if len(updates):
				fuzzed = dict(new_fuzzed)
				fuzzed['action'] = ",".join(updates)
				report_list[origin_domain].append(fuzzed)
	return report_list

def monitor_domains(domain_list = r"./domains.txt",data_file = r"./domainData.json",
base_options = {"registered":True,"geoip":True,"ssdeep":True,"nameservers":["8.8.8.8","4.4.4.4"],"threadcount":25},
new_origin_options = {}):
	""" This function is meant to monitor domains read from a new line delimited file.
	It will compare against ./domainData.json if it exists, if not results will be written there
	for future comparison. The base_options parameter is passed for all domains that dnstwist is run on.
	It is HIGHLY RECOMMENDED to leave "registered" set to True.
	The new_origin_options holds params that will be passed only to based domains not found in the data_file param.
	The results will be a diff of the data_file and the current run indicating what changed. 
	Return type will be a map with entries from domain_list file as keys and a list the corresponding 
	diffed dnstwist results as the values.
	"""
	fuzzed_domains = dict()
	current_list = dict()
	report_list = dict()
	comparison_keys = ['domain-name','dns-a','dns-aaaa','dns-ns','dns-mx']

	try:
		with open(domain_list,"r") as file:
			domains = [d.rstrip() for d in file.readlines()]
	except FileNotFoundError as err:
		print(err)
		raise

	print("Successfully imported domain monitor list.\nMonitoring {0} domains".format(len(domains)))

	# pulling from google's DNS for the time being
	# get all variations of fuzzed domains
	# if output file doesn't exist or domain not in list, use whois option
	if path.exists(data_file):
		with open(data_file,"r") as file:
			current_list = json.load(file)
	print("Successfully loaded previous data for {0} base domains".format(len(current_list.keys())))
	print("Starting domain twisting")
	for domain in domains:
		if domain not in current_list.keys():
			fuzzed_domains[domain] = dnstwister(domain,**new_origin_options,**base_options)
		else:
			fuzzed_domains[domain] = dnstwister(domain,**base_options)
	# alphabetically sort all the fuzzed domain results to simplify comparison
	print("Sorting domain results")
	for _, domain in fuzzed_domains.items():
		domain.sort(key=lambda d: d['domain-name'])

	# if no data file, it's all new
	# otherwise, compare the two lists
	if len(current_list.keys()) == 0:
		print("No previous base domains found. Treating all information as new.")
		report_list = dict(fuzzed_domains)
		for _, origin_domain in report_list.items():
			for domain in origin_domain:
				domain['action'] = 'added'
	else:
		# compare logic adding changed domains with status
		print("Comparing new results against data file...")
		report_list = compareData(current_list,fuzzed_domains,comparison_keys)
		for key, origin_domain in report_list.items():
			# adding this to avoid mass whois lookups; 
			# allows us to multithread the rest of the domain lookups,
			# get only those that are registered,
			# and then to go back for a significantly smaller subset 
			# single threaded for whois to avoid IP blocking
			print("Checking whois information for {0}".format(key))
			for domain in origin_domain:
				try:
					whoisdb = whois.query(domain['domain-name'])
					domain['whois-created'] = str(whoisdb.creation_date).split(' ')[0]
					domain['whois-updated'] = str(whoisdb.last_updated).split(' ')[0]
				except:
					domain['whois-created'] = str()
					domain['whois-updated'] = str()

	# overwrite the datafile with newest results
	print("Writing new results to data file")
	with open(data_file,"w") as outfile:
		json.dump(fuzzed_domains, outfile)

	#TODO: fire off report by whatever means 
	return report_list

if __name__ == "__main__":
	monitor_domains()