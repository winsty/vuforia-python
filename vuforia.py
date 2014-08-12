#!/usr/bin/env python
# Copyright 2013

"""Simple VWS client implementation using python.

The client supports add, update, retrieving, delete and listing targets
on a Vuforia Cloud Database.
"""

import hmac
import hashlib
import base64
import json

from time import strftime, gmtime
from httplib import HTTPSConnection


class Vuforia(object):
    """A blocking vuforia vws client.

    This class is used to interacte with VWS API, it implements all the
    operations defined in this module.
    """

    def __init__(self, access_key, secret_key, host='vws.vuforia.com'):
        self.host = host  # https://vws.vuforia.com.

        # access_key and secret_key is provided when you set up your
        # Cloud Recognition Database, you can retrieve these values from
        # the Target Manager at any time.
        self.access_key = access_key
        self.secret_key = secret_key

    def _gmtnow(self):
        """Return GMT time."""

        return strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())

    def _build_authorization(self, method, request_path, date,
                             content_type='', content=''):
        """Calculate the signature string from the http request.

        signature = base64(hmac-sha1(secret_key, string_to_sign))
        string_to_sign =
            HTTP-Verb + '\n' +     # HTTP request method.
            Content-MD5 + '\n' +   # Hexdecimal MD5 hash of the whole request body.
                                   # Use an empty string if the body is empty.

            Content-Type + '\n' +  # The content type of the request body. Use an
                                   # empty string for request types without body.

            Date + '\n' +          # Current date in GMT format,
                                   # e.g.: Sun, 22 Apr 2013 09:24:28 GMT
            Request-Path           # Request path in url.
        """

        # The md5 hash needs to be transformed to hexdecimal.
        content_md5 = hashlib.md5(content).hexdigest()

        string_to_sign = '\n'.join([method,
                                    content_md5,
                                    content_type,
                                    date,
                                    request_path])

        # Calculate hmac-sha1 hash string using secret_key.
        sign_sha1_hash_digest = hmac.new(self.secret_key,
                                         string_to_sign, hashlib.sha1).digest()

        # The sha1 hash needs to be transformed to base64.
        signature = base64.b64encode(sign_sha1_hash_digest)

        return 'VWS ' + self.access_key + ':' + signature

    def _do_request(self, method, request_path, body=None, headers=None):
        """Execute the HTTP request and return the response.
        """
        conn = HTTPSConnection(host=self.host, port=443)
        try:
            conn.request(method=method, url=request_path,
                         body=body, headers=headers)
            response = conn.getresponse()
            body = response.read()
        finally:
            conn.close()

        return (response.status, response.reason), json.loads(body)

    def add_target(self, target):
        """Add target.

        Add a new target into your database, it performs a HTTPS POST
        on https://{host}/targets and return the http response.
        """

        request_path = '/targets'
        method = 'POST'
        date_value = self._gmtnow()
        content_type = 'application/json'

        content = json.dumps(target)

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value,
                                                  content_type=content_type,
                                                  content=content)
        headers = {
            'Date': date_value,
            'Content-Type': content_type + '; charset=utf-8',
            'Authorization': authorization,
        }

        return self._do_request(method=method, request_path=request_path,
                                body=content, headers=headers)

    def update_target(self, target_id, updates):
        """Update target.

        Update target information in database by target_id, it performs
        a HTTPS PUT on https://{host}/targets/{target_id} and return
        the response.
        """

        request_path = '/targets/' + target_id
        method = 'PUT'
        date_value = self._gmtnow()
        content_type = "application/json"

        content = json.dumps(updates)

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value,
                                                  content_type=content_type,
                                                  content=content)
        headers = {
            'Date': date_value,
            'Content-Type': content_type + '; charset=utf-8',
            'Authorization': authorization
        }

        return self._do_request(method=method,
                                request_path=request_path,
                                body=content,
                                headers=headers)

    def get_target_by_id(self, target_id):
        """Get target information.

        Retrieve target information of target in your Cloud Recongnition
        Database by target_id, it performs a HTTPS GET on
                   https://{host}/targets/{target_id}
        and return the response.
        """

        request_path = '/targets/' + target_id
        method = 'GET'
        date_value = self._gmtnow()

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value)
        headers = {
            'Date': date_value,
            'Authorization': authorization
        }

        return self._do_request(method=method,
                                request_path=request_path,
                                headers=headers)

    def delete_target(self, target_id):
        """Delete a target from your Cloud Recognition Database by target_id,
        it performs a HTTPS DELETE on https://{host}/targets/{target_id} and
        return the response.
        """

        request_path = '/targets/' + target_id
        method = 'DELETE'
        date_value = self._gmtnow()

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value)
        headers = {
            'Date': date_value,
            'Authorization': authorization
        }

        return self._do_request(method=method, request_path=request_path,
                                headers=headers)

    def list_targets(self):
        """Get target list on vuforia database.

        Retrieve all the target_ids from your Cloud Recognition
        Database, it performs a HTTPS GET on https://{host}/targets.
        """

        request_path = '/targets'
        method = 'GET'
        date_value = self._gmtnow()

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value)
        headers = {
            'Date': date_value,
            'Authorization': authorization
        }

        return self._do_request(method=method, request_path=request_path,
                                headers=headers)

    def get_target_summary(self, target_id):
        """Get target summary on vuforia Database.
        """

        request_path = '/summary/' + target_id
        method = 'GET'
        date_value = self._gmtnow()

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value)
        headers = {
            'Date': date_value,
            'Authorization': authorization
        }

        return self._do_request(method=method, request_path=request_path,
                                headers=headers)

    def get_db_summary(self):
        """Get summary of remote vuforia database.

        It performs a HTTPS GET on https://{host}/summary.
        """

        request_path = '/summary'
        method = 'GET'
        date_value = self._gmtnow()

        authorization = self._build_authorization(method=method,
                                                  request_path=request_path,
                                                  date=date_value)
        headers = {
            'Date': date_value,
            'Authorization': authorization
        }

        return self._do_request(method=method, request_path=request_path,
                                headers=headers)

    def close(self):
        """Nothing to do."""
        pass

