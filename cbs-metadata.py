#!/usr/bin/env python
# cbs_metadata, views or sets metadata for Cloud Block Storage volumes
# version: 0.0.1a
# Copyright 2018 Brian King
# License: Apache

import argparse
import datetime
from getpass import getpass
import json
import keyring
import os
import plac
import requests
import sys
import time
from time import time

def parse_units(keyvalue):
    try:
        metakey, metavalue = keyvalue.split('=')
    except:
        print ("Syntax error, check your input.")
        sys.exit()
    return metakey, metavalue
    print("Syntax error, try again.")
    sys.exit()

def getset_keyring_credentials(username=None, password=None):
    """Method to retrieve credentials from keyring."""
    username = keyring.get_password("raxcloud", "username" )
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username' , username )
            print ("Username value saved in keychain as raxcloud username.")
        elif creds == "username":        
            username = input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username' , username )
            print ("Username value saved in keychain as raxcloud username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
    password = keyring.get_password("raxcloud", "password" )
    if password is None:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("raxcloud", 'password' , password )
        print ("API key value saved in keychain as raxcloud password.")
    return username, password

def wipe_keyring_credentials(username, password):
    """Wipe credentials from keyring."""
    try:
        keyring.delete_password('raxcloud', 'username')
        keyring.delete_password('raxcloud', 'password')
    except:
        pass

    return True


#Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()
        
    
    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code) 
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]
    return auth_token

def find_endpoints(auth_token):
    #init Cloud Servers endpoints as an empty list
    cbs_endpoints=[]
    #setting up api call
    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    headers = {'content-type': 'application/json', 'Accept': 'application/json',
               'X-Auth-Token': auth_token}
    raw_service_catalog = requests.get(url, headers=headers)
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]
    for service in range(len(endpoints)):
        if "cloudBlockStorage" == endpoints[service]["name"]:
            cbs_endpoints.append(endpoints[service]["publicURL"])
    return cbs_endpoints, headers

def find_cbs_endpoint(auth_token, headers, cbs_endpoints, volume):
    print ("Determining which region your cloud block storage volume is in...")
    for endpoint in range(len(cbs_endpoints)):
        potential_url = ( "%s/volumes/%s" % (cbs_endpoints[endpoint], volume) )
        potential_volume = requests.get(url=potential_url, headers=headers)
        if potential_volume.status_code == 200:
            volume_object = potential_volume
            region = potential_url.split('//')[1].split('.')[0]
            print ("Found volume %s in %s region" % (volume, region))
            break
    for endpoint in cbs_endpoints:
        if region in endpoint:
            cbs_endpoint = endpoint
    return cbs_endpoint, region

    #if we make it this far, the glance image UUID is invalid
    print ("Error! Rackspace Cloud Server Image UUID %s was not found." % (volume) )
    sys.exit()

def check_cbs_metadata(auth_token, headers, cbs_endpoint, volume):
    metadata_url = ( "%s/volumes/%s/metadata" % (cbs_endpoint, volume) )
    raw_cbs_metadata= requests.get(url=metadata_url, headers=headers)
    cbs_metadata = raw_cbs_metadata.json()
    print (cbs_metadata)

def set_cbs_metadata(auth_token, headers, cbs_endpoint, volume, metakey, metavalue):
    metadata_url = ( "%s/volumes/%s/metadata" % (cbs_endpoint, volume) )
    payload = {
    "metadata": {
        metakey : metavalue
                }
    }
    new_cbs_metadata= requests.post(url=metadata_url, headers=headers, json=payload)
    cbs_metadata = new_cbs_metadata.json()
    print (cbs_metadata)
    
    

@plac.annotations(
    volume=plac.Annotation("UUID of CBS volume"),
    verb=plac.Annotation("Either 'show' or 'set' CBS metadata value", 'positional', None, None, ['show', 'set'], None ),
    keyvalue=plac.Annotation("Metadata to set in key=value format", 'positional', None, str, None, None)
#ip_to_move=plac.Annotation("IP to move: valid choices are public, private, or both", 'positional', None, None, ['public', 'private', 'both'], None )
)
#def main(volume, region, verb):
def main(volume, verb, keyvalue):
    metakey, metavalue = parse_units(keyvalue)
    username,password = getset_keyring_credentials()
    auth_token = get_auth_token(username,password)
    cbs_endpoints, headers = find_endpoints(auth_token)
    cbs_endpoint, region = find_cbs_endpoint(auth_token, headers, cbs_endpoints, volume)
    set_cbs_metadata(auth_token, headers, cbs_endpoint, volume, metakey, metavalue)
    check_cbs_metadata(auth_token, headers, cbs_endpoint, volume)
if __name__ == '__main__':
    plac.call(main)