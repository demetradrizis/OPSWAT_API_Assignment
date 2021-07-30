import os
import sys
import io
from wsgiref import headers
import argparse
import requests
import hashlib
from pip._vendor import requests
import json
import time


def create_hash(hash, file):  # best chunk size is 65536
    # create the hash of a file using md5
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    with open(file, 'rb') as f:         #rb is used to 'read binary' of file
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    return "{0}".format(md5.hexdigest())        #return md5 hash


if __name__ == '__main__':
    #Steps- Parse arguments
    parser = argparse.ArgumentParser() #argparse module makes it easy to write user-friendly command-line interfaces.
    parser.add_argument("-f", "--file", dest="file", required=True, #Add a file via command line is REQUIRED (required = true)
                        help="File to be Scanned")
    parser.add_argument("-k", "--apikey", dest="apikey", required =True, #Use of an API Key by command line is REQUIRED (required = true)
                        help="Use API Key here")
    parser.add_argument("-hash", "--hash", dest="hash", required=False, default="md5", #defaults to md5 hash if command line argument isn't specified
                        help="default md5")
    parser.add_argument("-m", "--meta", dest="metadata", required=False, default=None, #Used for file metadata when calling API
                        help="Metadata for File")

    args = parser.parse_args() #saves all of the arguments used in args variable
    file_hash = create_hash(args.hash, args.file).upper()  #Calls create_hash function -> sends hash of file and the filename
    filename = args.file #filename is saved here for later use (ex: test.txt)
    url = "https://api.metadefender.com/v4/hash/{0}".format(file_hash)

    headers = {'apikey': args.apikey, 'file-metadata': args.metadata} #Dictionary of HTTP Headers to send with the API Request
    # headers = {'apikey': "a166c3fb8be911b1d46179711037789e", 'file-metadata': args.metadata} #this will work the same as above^
    myURL= 'https://api.metadefender.com/v4/'

    url = myURL + 'hash/' + file_hash       #hash lookup to get scan report
    header = {'apikey': args.apikey}
    response = requests.get(url, headers=header)

    # if file was not found, return False
    if response.status_code == 404:
        sc = False
    # if error, exit
    elif response.status_code != 200:
        sys.exit(0)
    # else continue and save report in sc
    else:   
        sc = response.json()

    try:
        response = requests.get(url=url, headers=headers) #sends get request to the URL/api with the http headers containing API Key and File Metadata)
        MyResponse = response.json() #saves the HTTP Response in JSON format
    except requests.exceptions.HTTPError as http_error: #Add More HTTP errors like 405, 407 etc
        print("404 Error:", http_error) #error handling
        sys.exit(0)
    except requests.exceptions.Timeout as timeout:
        print("Session Timeout:", timeout) #error handling
        sys.exit(0)

    #upload the file into the API if the hash was not found
    if not sc:
        url = "https://api.metadefender.com/v4/" + 'file'
        file = open(filename, "rb")                         #rb is used to 'read binary' of file
        
        headers = {'apikey': args.apikey, 'content-type': 'application/octet-stream',
                  'filename': filename}
        response = requests.post(url=url, headers=headers, data=file) #sends get request to the URL/api with the http headers containing API Key and File Metadata)
        #print(response) 200 OK
        data_id = response.json()['data_id'] #retrieve data id after upload

        newurl = "https://api.metadefender.com/v4/" + 'file/' + data_id #holds the url of the file + data_id
        headers = {'apikey' : args.apikey}

        start_time = time.time()                #keeps track of time 
        current_time = time.time()

        while current_time - start_time <= 300.0:   #if report isn't complete for 5 mins    
            response = requests.get(url=newurl, headers=headers)  
            report = response.json()                    #get the report in json format
            if report['scan_results']['progress_percentage'] == 100:    #return the report if complete
                break
            time.sleep(5)
            current_time = time.time()

        print("\nScan Report")          #prints response in a specific format
        if 'display_name' in report['file_info']:
            print("\n")
            print("\nfilename:", report['file_info']['display_name'])
            print("overall_status:", report['scan_results']['scan_all_result_a'])

            for engine, result in report['scan_results']['scan_details'].items():
                print("engine:", engine)                                            #use a nested loop to iterate through the report to get necessary info

                if result['scan_result_i'] == 0:
                    print("threat_found: Clean")

                else:
                    print('threat_found:', result['threat_found'])
                print("scan_result: ", result['scan_result_i'])
                print("def_time:", result['def_time'])
                print("\n")

        sys.exit(0)


    if "Endpoint not found" not in MyResponse.values(): #uses scan results and scan details as the key to value in the dictionary (MyResponse)
        #print out if the file was already scanned
        print("\n")
        print("filename: {file_name}".format(file_name=filename)) #print out the filename
        print("overall_status: {status}".format(status=MyResponse['scan_results']['scan_all_result_a']))
        for f, c in MyResponse['scan_results']['scan_details'].items():         #use a nested loop to iterate through to print out each key and value
            print("engine: {engine}".format(engine=f)) #repeats for each engine
            print("threat_found: {thread}".format(thread=c['threat_found'] 
                if c['threat_found'] 
                else 'Clean'))
            print("scan_result: {result}".format(result=c['scan_result_i']))
            print("def_time: {time}".format(time=c['def_time']))
            print("\n")
        sys.exit(0)
        
