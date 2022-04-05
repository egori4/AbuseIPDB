import requests
import json
import os
import csv

raw_data_path = "./Raw Data/"
report_path = "./Report/"
api_key = '1331ffc49bbd5c9f4ebdbea55e0e8c3f98e91fa8a43cb6c675c3f5ba324fbb3f790db5849fe84131'

if not os.path.exists('./Raw Data'):
	os.makedirs('./Raw Data')

if not os.path.exists('./Report'):
	os.makedirs('./Report')


with open(report_path + 'abuseipdb_report.csv', mode='w', newline="") as abuseipdb_report:
		bdos_writer = csv.writer(abuseipdb_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		bdos_writer.writerow(['IP Address' , 'Abuse Score' , 'Country' , 'Type' , 'ISP' , 'Domain', 'Hosnames', 'Total Reports', 'Distinct Users' , 'Last reported'])



aipdb_dict = {}
aipdb_dict['Src IP details'] = []

def AbuseIPDBCall(ipAddress):
	
	url = 'https://api.abuseipdb.com/api/v2/check'

	querystring = {
		'ipAddress': ipAddress,
		'maxAgeInDays': '90'
	}

	headers = {
		'Accept': 'application/json',
		'Key': api_key
	}

	response = requests.request(method='GET', url=url, headers=headers, params=querystring)

	# Formatted output
	decodedResponse = json.loads(response.text)
	# print(json.dumps(decodedResponse, sort_keys=True, indent=4))

	aipdb_dict['Src IP details'].append(decodedResponse)

	with open(report_path + 'abuseipdb_report.csv', mode='a', newline="") as abuseipdb_report:
		bdos_writer = csv.writer(abuseipdb_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		bdos_writer.writerow([f'{decodedResponse["data"]["ipAddress"]}' , f'{decodedResponse["data"]["abuseConfidenceScore"]}' , f'{decodedResponse["data"]["countryCode"]}' , f'{decodedResponse["data"]["usageType"]}' , f'{decodedResponse["data"]["isp"]}' , f'{decodedResponse["data"]["domain"]}', f'{decodedResponse["data"]["hostnames"]}', f'{decodedResponse["data"]["totalReports"]}', f'{decodedResponse["data"]["numDistinctUsers"]}', f'{decodedResponse["data"]["lastReportedAt"]}'])

	with open(raw_data_path + 'AbuseIPDB.json', 'w') as outfile:
		json.dump(aipdb_dict,outfile)

	return

########### Read ip_list.txt, remove duplicate IPs, errors and add to python list ############


ip_list = [] # holds lines already seen

with open('ip_list.txt') as f:
	content = f.read().splitlines()
	f.seek(0)

	for ip in content:
		if ip not in ip_list:
			ip_list.append(ip)


for ip in ip_list:
	AbuseIPDBCall(ip)