# -*- coding: utf-8 -*-
"""
Author:
    Ryan Jones

Contact:
    ryan.jones@cofense.com

Version:
    0.01

Description:
    This Module provides an easy wrapper for the Cofense Triage, Vision and PhishMe API's to allow quick building an integration with other services.
    An intelligence Module is already available here: https://pypi.org/project/phishme-intelligence/
    The intelligence Modules documentation is available from here: https://threathq.com/docs/library_reference.html?highlight=python#python-package-usage

Todo:
    * Add https Requests capability with error handeling, it must be able to use self signed certs
    * Input validation for Hostnames, API Keys etc
    * Comlete all availble endpoint functions for Triage in the Triage class
    * Comlete all availble endpoint functions for Vision in the Vision class
    * Comlete all availble endpoint functions for PhishMe in the PhishMe class

"""

import requests
import validators
import urllib.parse
from urllib3.exceptions import InsecureRequestWarning
from collections import namedtuple
import json
import re



def normalise_hostname(host):
    """
    Description:
        Validates and Normalises hostname by:
            * Stripping whitespace either side of the URI
            * Prepending HTTPS if it is not present
            * Removing Trailing slashes
            * Validating the URI utilising the validators package
    Usage:
        normalise_hostname(hostname)
    Returned:
        Success:
            valid Hostname
        Failure:
            False
    """
    host = host.strip()
    p = urllib.parse.urlparse(host, 'https')
    netloc = p.netloc or p.path
    path = ''
    p = urllib.parse.ParseResult('https', netloc, path, *p[3:])
    host = p.geturl()
    if host.endswith('/'):
        host = host[:-1]
    if not validators.url(host):
        return False
    return host


def https_get_request(host, product, endpoint, key=0, email=0, strictssl=False, payload=None):

    # Suppress only the single warning from urllib3 needed.
    if strictssl is not True:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Build requests for Triage
    if product == 'triage':
        request_url = host + "/api/public/v1/" + endpoint
        headers = {
            'Authorization': "Token token=" + email + ":" + key,
            'User-Agent': 'Cofense python agent 0.01'
            }

    #r = requests.get('https://httpbin.org/get',timeout=15)

    r = requests.get(request_url, timeout=3, headers=headers, verify=strictssl, params=payload)
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        return "Http Error: " + str(errh)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as errc:
        return "Error Connecting: " + str(errc)
    except requests.exceptions.Timeout as errt:
        return "Timeout Error: " + str(errt)
    except requests.exceptions.TooManyRedirects as errr:
        return "To many redirects: " + str(errr)
    except requests.exceptions.RequestException as err:
        return "Undefined Error: Something Else has gone wrong " + str(err)
    
    # If all good in the neighbourhood return JSON
    #return r.headers
    #return r.json
    if 'next' in r.links.keys():
        next_url = r.links['next']['url']
    if 'last' in r.links.keys():
        last_url = r.links['last']['url']
    else:
        next_url = None
        last_url = None
    full_results = {"body": r.json(), "headers": r.headers, "next": next_url, "last": last_url}
    return full_results



# Lets begin with Triage
# Simple class that handles Auth and Requests, basic error handling
class triage:
    def __init__(self, email, key, host, strictssl=False,endpoint=''):
        self.email = email
        self.endpoint = endpoint
        self.key = key
        self.host = normalise_hostname(host)
        self.strictssl = strictssl


    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, h):
        if not h: raise Exception("You must enter in a valid hostname")
        self._host = h
    
    @property
    def email(self):
        return self._email
    
    @email.setter
    def email(self, e):
        if not validators.email(e): raise Exception("You must enter in a valid Email")
        self._email = e


    
    def categories(self, cat_id=None):
        # Request for a single category
        if cat_id is not None:
            new_endpoint = str("categories/{0}").format(cat_id)
            result=https_get_request(host=self.host, product="triage", endpoint=new_endpoint, key=self.key, email=self.email, strictssl=self.strictssl)
        # Request for all categories
        else:
            result=https_get_request(host=self.host, product="triage", endpoint="categories", key=self.key, email=self.email, strictssl=self.strictssl)
        return json.dumps(result['body'])
        #return "key: " + self.key + "\nHost: " + self.host + "\nEmail: " + self.email + "\nEndpoint: " + self.endpoint + "\nStrict SSL: " + self.strictssl

    def clusters(self, cluster_id=None, match_priority=None, tags=None, start_date=None, end_date=None, page=None, per_page=50, bulk_results=None):
        # Return results for a single cluster
        if cluster_id is not None:
            new_endpoint = str("clusters/{0}").format(cluster_id)
            result=https_get_request(host=self.host, product="triage", endpoint=new_endpoint, key=self.key, email=self.email, strictssl=self.strictssl)
            return json.dumps(result['body'])
        else:
            # If bulk_results is used to get a JSON Object with more than 50 results, which is what they'd get with a single request then we need to calculate the following
            # the remainder from dividing the number by 50 (modulo)
            # remove that from the full_pages number and divide by 50 to get the total number of FULL (50 per page) requests that have to be made
            # make each request incrementing the current page and joining the JSON results
            # check to see if the current page is the last page if so we can break there
            # make the last request for the remainder setting per page to be the remainder and the page number to be the current_page and join to results
            # As each result id returned we need to check the rellinks to see if a next exists
            if bulk_results and bulk_results > 50:
                remainder = bulk_results % 50
                full_pages = int((bulk_results - remainder) / 50)
                current_page = 0
                final_result = None
                while current_page != full_pages:
                    current_page += 1
                    last_page = None
                    payload={'match_priority': match_priority, 'tags': tags, 'start_date': start_date, 'end_date': end_date, 'page': current_page, 'per_page': 50}
                    result=https_get_request(host=self.host, product="triage", endpoint="clusters", key=self.key, email=self.email, strictssl=self.strictssl, payload=payload)
                    if current_page == 1:
                        final_result = result['body']
                    if current_page > 1:
                        for item in result['body']:
                            final_result.append(item)

                    if current_page == 1 and result['last']:
                        match = re.search(r'((\?|&)page=)(?P<page>[0-9]{1,100})', result['last'])
                        last_page = match.group('page')
                    if last_page:
                        if current_page == last_page:
                            break
                    if int(current_page) == int(full_pages):
                        break
                
                if int(remainder) and last_page and int(current_page) != int(last_page):
                    current_page += 1
                    payload={'match_priority': match_priority, 'tags': tags, 'start_date': start_date, 'end_date': end_date, 'page': current_page, 'per_page': remainder}
                    result=https_get_request(host=self.host, product="triage", endpoint="clusters", key=self.key, email=self.email, strictssl=self.strictssl, payload=payload)
                    for item in result['body']:
                        final_result.append(item)
                    #
                    # Need to concat JSON here
                    #
                    # return result here
                return json.dumps(final_result)
            # If they have set the total results variable for some reason as 50 or less then we just need to change the per page to total results
            if bulk_results and bulk_results <= 50:
                payload={'match_priority': match_priority, 'tags': tags, 'start_date': start_date, 'end_date': end_date, 'page': page, 'per_page': bulk_results}
                result=https_get_request(host=self.host, product="triage", endpoint="clusters", key=self.key, email=self.email, strictssl=self.strictssl, payload=payload)
                return json.dumps(result['body'])
            if not bulk_results:
                payload={'match_priority': match_priority, 'tags': tags, 'start_date': start_date, 'end_date': end_date, 'page': page, 'per_page': per_page}
                result=https_get_request(host=self.host, product="triage", endpoint="clusters", key=self.key, email=self.email, strictssl=self.strictssl, payload=payload)
                return json.dumps(result['body'])
        
    def cluster_last(self):
        result=https_get_request(host=self.host, product="triage", endpoint="cluster_last", key=self.key, email=self.email, strictssl=self.strictssl)
        return json.dumps(result['body'])
    
    def integration_search(self, sha256=None, md5=None, url=None):
        pass