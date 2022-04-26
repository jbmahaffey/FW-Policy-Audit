#!/usr/bin/env python3

import requests
import argparse
import csv
import ssl
import logging
import pprint

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fortigate', default='jmahaffey-fgt-api.fortidemo.fortinet.com:10403', help='Firewall IP Address')
    parser.add_argument('--token', default='', help='API Token')
    args = parser.parse_args() 

    headers = {
        'Authorization': 'Bearer' + args.token, 
        'content-type': 'application/json'
        }
    
    url = 'https://{}/api/v2/cmdb/firewall/policy/?access_token={}'.format(args.fortigate, args.token)

    try:
        # Connect to Fortigate and pull policies
        policies = requests.get(url, headers=headers)
        policiesjson = policies.json()
    except:
        logging.error('Unable to login to FortiGate')

    slimdat = []
    for dat in policiesjson['results']:
        slist = []
        saddlist = []
        dlist = []
        daddlist = []
        for sname in dat['srcintf']:
            slist.append(sname['name'])
        for sadd in dat['srcaddr']:
            saddlist.append(sadd['name'])
        for dname in dat['dstintf']:
            dlist.append(dname['name'])
        for dadd in dat['dstaddr']:
            daddlist.append(dadd['name'])
        slimdat.append(
            {
            'name': dat['name'],
            'policyid': dat['policyid'], 
            'srcintf': slist,
            'srcaddr': saddlist,
            'dstintf': dlist,
            'dstaddr': daddlist,
            'webfilter-profile': dat['webfilter-profile'],
            'action': dat['action'],
            'status': dat['status']
            }
            )

    # Write logs to csv file
    data_file = open('Policies.csv', 'w')
    csv_writer = csv.writer(data_file)
    count = 0
    for pol in slimdat:
        if count == 0:
            header = pol.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(pol.values())
    data_file.close()

if __name__ == '__main__':
    main()