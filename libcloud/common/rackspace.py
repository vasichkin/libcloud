# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Common utilities for Rackspace Cloud Servers and Cloud Files
"""
import httplib
from urllib2 import urlparse
from libcloud.common.base import ConnectionUserAndKey
from libcloud.compute.types import InvalidCredsError

AUTH_HOST_US='auth.api.rackspacecloud.com'
AUTH_HOST_UK='lon.auth.api.rackspacecloud.com'
AUTH_API_VERSION = 'v1.0'

__all__ = [
    "RackspaceBaseConnection",
    "AUTH_HOST_US",
    "AUTH_HOST_UK"
    ]

class RackspaceBaseConnection(ConnectionUserAndKey):
    def __init__(self, user_id, key, secure, host=None, port=None):
        self.cdn_management_url = None
        self.storage_url = None
        self.auth_token = None
        self.request_path = None
        self.__host = host
        super(RackspaceBaseConnection, self).__init__(
            user_id, key, secure=secure, host=host, port=port)

    def add_default_headers(self, headers):
        headers['X-Auth-Token'] = self.auth_token
        headers['Accept'] = "application/xml"
        return headers

    def _auth(self):
        conn = None
        try:
            conn = self.conn_classes[self.secure](
                self.auth_host, self.port[self.secure])
            conn.request(
                method='GET',
                url='/%s' % (AUTH_API_VERSION),
                headers={
                    'X-Auth-User': self.user_id,
                    'X-Auth-Key': self.key
                }
            )

            resp = conn.getresponse()

            if resp.status != httplib.NO_CONTENT:
                raise InvalidCredsError()

            headers = dict(resp.getheaders())

            try:
                self.server_url = headers['x-server-management-url']
                self.storage_url = headers['x-storage-url']
                self.cdn_management_url = headers['x-cdn-management-url']
                self.lb_url = self.server_url.replace("servers", "ord.loadbalancers")
                self.auth_token = headers['x-auth-token']
            except KeyError:
                raise InvalidCredsError()

            scheme, server, self.request_path, param, query, fragment = (
                urlparse.urlparse(getattr(self, self._url_key)))

            # Set host to where we want to make further requests to;
            self.__host = server
        finally:
            if conn:
                conn.close()

    def request(self, action, params=None, data='', headers=None,
                method='GET', raw=False):

        if not self.auth_token:
            self._auth()

        attempt = 0
        response = None
        
        while attempt < 2:
            response = super(RackspaceBaseConnection, self).request(
                action=action,
                params=params, data=data,
                method=method, headers=headers
            )

            if response.status != 401:
                return response
            else:
                #auth token expired, need to refresh it and retry once
                attempt += 1
                self._auth()

        return response

    def _get_host(self):
        """
        Getter for host property - since it's taken from auth endpoint
        we have to take authentication first
        """

        if not self.__host:
            self._auth()

        return self.__host

    def _set_host(self, host):
        self.__host = host


    host = property(_get_host, _set_host)
