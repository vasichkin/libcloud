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
import unittest
import httplib

from libcloud.compute.drivers.openstack import OpenStackNodeDriver

from test import MockHttp
from test.compute import TestCaseMixin
from test.file_fixtures import ComputeFileFixtures

class OpenStackTests(unittest.TestCase, TestCaseMixin):

    def setUp(self):
        self.user = 'TestUser'
        self.key = 'TestKey'
        self.url = 'http://test.url.com:3333/v1.0/'
        OpenStackNodeDriver.connectionCls.conn_classes = (OpenStackMockHttp, OpenStackMockHttp)
        OpenStackMockHttp.type = None
        self.driver = OpenStackNodeDriver(user_name=self.user, api_key=self.key, url=self.url)

class OpenStackMockHttp(MockHttp):

    fixtures = ComputeFileFixtures('openstack')

    def _form_fixture_name(self, method, url, body, headers):
        import re
        from urllib2 import urlparse
        parsed = urlparse.urlparse(url)
        scheme, netloc, path, params, query, fragment = parsed
        action = re.sub('^/v[1-9]\.[0-9]', '', path)
        action = action.replace('/','_')
        
        accept = headers.get('accept')
        ext = (not accept or re.search('/json$',accept)) and '.json' or '.xml'

        return method.lower()+action+ext

    def _v1_0(self, method, url, body, headers):
        headers = {'x-server-management-url': 'http://faked.openstack.test.com/v1.0',
                   'x-auth-token': 'faked-x-auth-token-for-test',
                   'x-cdn-management-url': '' #TODO verify normal auth response
                    }
        return httplib.NO_CONTENT, "", headers, httplib.responses[httplib.NO_CONTENT]

    def _v1_0_servers_detail(self, method, url, body, headers):
        body = self.fixtures.load(self._form_fixture_name(method, url, body, headers))
        return httplib.OK, body, {}, httplib.responses[httplib.OK]

    def _v1_0_flavors_detail(self, method, url, body, headers):
        body = self.fixtures.load(self._form_fixture_name(method, url, body, headers))
        return httplib.OK, body, {}, httplib.responses[httplib.OK]

    def _v1_0_images_detail(self, method, url, body, headers):
        body = self.fixtures.load(self._form_fixture_name(method, url, body, headers))
        return httplib.OK, body, {}, httplib.responses[httplib.OK]

    def _v1_0_servers(self, method, url, body, headers):
        body = self.fixtures.load(self._form_fixture_name(method, url, body, headers))
        return httplib.OK, body, {}, httplib.responses[httplib.OK]

    def _v1_0_servers_1234(self, method, url, body, headers):
        # invoked on /servers/1234,  1234 is the first server id in get_servers_detail.json fixture
        return httplib.OK, body, {}, httplib.responses[httplib.OK]

    def _v1_0_servers_1234_action(self, method, url, body, headers):
        # invoked on /servers/1234/action, 1234 is the first server id in get_servers_detail.json fixture
        return httplib.OK, body, {}, httplib.responses[httplib.OK]

if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
