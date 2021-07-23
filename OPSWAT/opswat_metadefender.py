import os
import sys
import io
from wsgiref import headers
import argparse
import requests
import hashlib
from pip._vendor import requests
import hashlib
import sys
import json

def create_hash(hash, file):  # best chunk size is 65536
    # determine the hash of a file
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    return "{0}".format(md5.hexdigest())

if __name__ == '__main__':
    #Steps- Parse arguments
    parser = argparse.ArgumentParser() #argparse module makes it easy to write user-friendly command-line interfaces.
    parser.add_argument("-f", "--file", dest="file", required=True, #Add a file via command line is REQUIRED (require = true)
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

    try:
        response = requests.get(url=url, headers=headers) #sends get request to the URL/api with the http headers containing API Key and File Metadata)
        MyResponse = response.json() #saves the HTTP Response in JSON format
    except requests.exceptions.HTTPError as http_error: #Add More HTTP errors like 405, 407 etc
        print("404 Error:", http_error) #error handling
        sys.exit(0)
    except requests.exceptions.Timeout as timeout:
        print("Session Timeout:", timeout) #error handling
        sys.exit(0)
    #3: cached -> step 6
    if "Not Found" not in MyResponse.values():
        # print("Hash Found.")
        # output(MyResponse, args.file)
        print ("\n")
        print("filename: {file_name}".format(file_name=filename)) #print out the filename
        print("overall_status: {status}".format(status=MyResponse['scan_results']['scan_all_result_a']))
        for f, c in MyResponse['scan_results']['scan_details'].items():
            print("engine: {engine}".format(engine=f)) #repeats for each engine
            print("threat_found: {thread}".format(thread=c['threat_found'] if c['threat_found'] else 'Clean'))
            print("scan_result: {result}".format(result=c['scan_result_i']))
            print("def_time: {time}".format(time=c['def_time']))
            print("\n")
        sys.exit(0)


    else:
         URI = "https://api.metadefender.com/v4/" + 'file'
         file = open(filename, "rb")
