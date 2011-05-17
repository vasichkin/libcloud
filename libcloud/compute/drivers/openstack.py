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

""" OpenStack driver """

import httplib
import json
import urlparse

from libcloud.common.types import MalformedResponseError, InvalidCredsError
from libcloud.compute.types import NodeState, Provider
from libcloud.compute.base import Node, NodeLocation
from libcloud.compute.base import NodeSize, NodeImage
from libcloud.compute.drivers.rackspace import MossoBasedNodeDriver
from libcloud.compute.drivers.rackspace import MossoBasedResponse
from libcloud.compute.drivers.rackspace import MossoBasedConnection


class OpenStackResponse(MossoBasedResponse):
    """ OpenStack specific response """

    def parse_body(self):
        if not self.body:
            return None
        try:
            body = json.loads(self.body)
        except:
            raise MalformedResponseError("Failed to parse JSON",
                                         body=self.body,
                                         driver=OpenStackNodeDriver)
        return body

    def parse_error(self):
        """Used in to form message for exception to raise in case self.status is not OK"""
        return '%s %s' % (self.status, self.error)


class OpenStackConnection(MossoBasedConnection):
    """ Connection class for the OpenStack driver """
    
    responseCls = OpenStackResponse

    def __init__(self, user_name, api_key, url, secure):
        self.server_url = url
        r = urlparse.urlparse(url)

        # here we rely on path structure like
        # http://hostname:port/v1.0 so path=path_version
        self.api_version = r.path
        self.auth_token = None
        super(OpenStackConnection, self).__init__(user_id=user_name,
                                                  key=api_key,
                                                  secure=secure,
                                                  host=r.hostname,
                                                  port=r.port)

    def encode_data(self, data):
        return data

    def _set_additional_headers(self, action, params, data, headers, method):
        if method in ("POST", "PUT"):
            headers['Content-Type'] = 'application/json'

    def add_default_headers(self, headers):
        headers['X-Auth-Token'] = self.auth_token
        headers['Accept'] = 'application/json'
        return headers

    def _auth(self):
        """ OpenStack needs first to get an authentication token """
        
        self.connection.request(
            method='GET',
            url=self.api_version,
            headers={'X-Auth-User': self.user_id, 'X-Auth-Key': self.key}
        )

        resp = self.connection.getresponse()

        if resp.status != httplib.NO_CONTENT:
            raise InvalidCredsError()

        headers = dict(resp.getheaders())

        try:
            self.server_url = headers['x-server-management-url']
            self.auth_token = headers['x-auth-token']
        except KeyError:
            raise InvalidCredsError()


class OpenStackNodeDriver(MossoBasedNodeDriver):
    """ OpenStack node driver. """
    connectionCls = OpenStackConnection
    name = 'OpenStack'
    type = Provider.OPENSTACK

    features = {"create_node": ["generates_password"]}

    NODE_STATE_MAP = { 'BUILD': NodeState.PENDING,
                       'REBUILD': NodeState.PENDING,
                       'ACTIVE': NodeState.RUNNING,
                       'SUSPENDED': NodeState.TERMINATED,
                       'QUEUE_RESIZE': NodeState.PENDING,
                       'PREP_RESIZE': NodeState.PENDING,
                       'VERIFY_RESIZE': NodeState.RUNNING,
                       'PASSWORD': NodeState.PENDING,
                       'RESIZE': NodeState.PENDING,
                       'RESCUE': NodeState.PENDING,
                       'REBOOT': NodeState.REBOOTING,
                       'HARD_REBOOT': NodeState.REBOOTING,
                       'DELETE_IP': NodeState.PENDING,
                       'UNKNOWN': NodeState.UNKNOWN}

    def __init__(self, user_name, api_key, url, secure=False):
        """
        user_name NOVA_USERNAME as reported by OpenStack
        api_key NOVA_API_KEY as reported by OpenStack
        url NOVA_URL as reported by OpenStack.
        secure use HTTPS or HTTP. Note: currently only HTTP
        """

        self.connection = OpenStackConnection(user_name=user_name,
                                              api_key=api_key,
                                              url=url, secure= secure)
        self.connection.driver = self
        self.connection.connect()

    def list_locations(self):
        """Lists available locations. So far there is no public locations
        so we return fake location
        """

        return [NodeLocation(id=0, name='OpenStack is private cloud',
                             country='NoCountry', driver=self)]

    def ex_list_flavors(self):
        self.list_sizes()

    def _to_sizes(self, flavors_dict):
        try:
            flavors = flavors_dict['flavors']
        except KeyError:
            raise MalformedResponseError(value='no flavors-values clause',
                                         body=flavors_dict, driver=self)
        return [ self._to_size(value) for value in flavors ]

    def _to_size(self, el):
        s = OpenstackNodeSize(id=el.get('id'),
                     ram=int(el.get('ram')),
                     disk=int(el.get('disk')),
                     name=el.get('name'),
                     price=None,
                     bandwidth=None,
                     driver=self.connection.driver,
                     links=el.get('links'))
        return s
    
    def _to_images(self, images_dict):
        try:
            images = images_dict['images']
        except KeyError:
            raise MalformedResponseError(value='no images clause',
                                         body=images_dict, driver=self)
        #filter out all inactive images, since there's no way to tell client image is not ok
        return [ self._to_image(image)
                 for image in images if image.get('status') == 'ACTIVE' ]

    def _to_image(self, el):
        image = NodeImage(id=el.get('id'),
                          name=el.get('name'),
                          driver=self.connection.driver,
                          extra={'updated': el.get('updated'),
                                 'links': el.get('links')}
        )
        return image

    def _to_nodes(self, servers_dict):
        try:
            servers = servers_dict['servers']
        except KeyError:
            raise MalformedResponseError(value='no servers-values clause',
                                         body=servers_dict, driver=self)
        return [ self._to_node(server) for server in servers ]

    def ex_list_servers(self):
        self.list_nodes()

    def create_node(self, **kwargs):
        """Create a new node

        See L{NodeDriver.create_node} for more keyword args, some of them:
            ex_metadata: dict of Key/Value metadata to associate with a node
            ex_files: dict {filename: content} to be injected to VM
        """
        name = kwargs['name']
        node_image = kwargs['image']
        node_size = kwargs['size']
        ex_metadata = kwargs.get('ex_metadata')
        ex_personality = kwargs.get('ex_personality')

        flavorRef = node_size.links[0]['href']
        imageRef = node_image.extra['links'][0]['href']
        request = {'server': {'name': name, 'flavorRef': flavorRef,
                              'imageRef': imageRef}}
        if ex_metadata:
            request['server']['metadata'] = ex_metadata
        if ex_personality:
            request['server']['personality'] = ex_personality

        data = json.dumps(request)
        resp = self.connection.request("/servers", method='POST', data=data)
        try:
            server_dict = resp.object['server']
        except KeyError:
            raise MalformedResponseError(value='no server clause',
                                         body=resp.object, driver=self)
        return self._to_node(server_dict=server_dict)

    def _to_node(self, server_dict):
        """ Here we expect a dictionary which is under the clause server
        or servers in /servers or /servers/detail
        """

        ips = OpenStackIps(server_dict['addresses'])

        n = Node(id=server_dict.get('id'),
                 name=server_dict.get('name'),
                 state=self.NODE_STATE_MAP.get(server_dict.get('status'),
                                               NodeState.UNKNOWN),
                 public_ip=ips.public_ipv4, #list of addresses
                 private_ip=ips.private_ipv4, #list of addresses
                 driver=self.connection.driver,
                 extra={
                    'adminPass': server_dict.get('adminPass'),
                    'affinityId': server_dict.get('affinityId'),
                    'created': server_dict.get('created'),
                    'flavorRef': server_dict.get('flavorRef'),
                    'hostId': server_dict.get('hostId'),
                    'id': server_dict.get('id'),
                    'imageRef': server_dict.get('imageRef'),
                    'links':  server_dict.get('links'),
                    'metadata': server_dict.get('metadata'),
                    'progress': server_dict.get('progress')
                 })
        return n

    def ex_rebuild(self, node_id, image_ref):
        body = {"rebuild" : {"imageRef" : image_ref}}
        resp = self._node_action(node_id, body=body)
        return resp.status == 202

    def _node_action(self, node, body):
        return super(OpenStackNodeDriver, self)._node_action(node,
                                                             json.dumps(body))

    def ex_limits(self):
        resp = self.connection.request('/limits', method='GET')
        return resp.object['limits']


class OpenStackIps(object):
    """ Contains the list of public and private IPs """

    public_ipv4 = []
    private_ipv4 = []
    public_ipv6 = []
    private_ipv6 = []
    def __init__(self, ip_list):
        self._separate_by_protocol(ip_list['public'],
                                   self.public_ipv4, self.public_ipv6)
        self._separate_by_protocol(ip_list['private'],
                                   self.private_ipv4, self.private_ipv6)

    def _separate_by_protocol(self, input_list, out_list_v4, out_list_v6):
        """
        convert IP dictionary to list of the structure,
        note that out_list_v4 and out_list_v6 are modified
        """

        for ip in input_list:
            if ip['version'] == 4:
                out_list_v4.append(ip['addr'])
            if ip['version'] == 6:
                out_list_v6.append(ip['addr'])


class OpenstackNodeSize(NodeSize):
    """ extends base NodeSize with links section """
    links = []
    def __init__(self, id, name, ram, disk, bandwidth, price, driver, links):
        super(OpenstackNodeSize, self).__init__(id, name, ram, disk,
                                                bandwidth, price, driver)
        self.links = links
