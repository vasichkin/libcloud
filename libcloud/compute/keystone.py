from libcloud.common.rackspace import RackspaceBaseConnection
import urllib

class KeystoneAuth(RackspaceBaseConnection):
    def _auth(self):
        auth_url = self.auth_path
        auth_type, auth_hostname, auth_port, auth_path = self._split_in_parts(auth_url)

        retry_v1_port = True
        redirected = False

        headers={
            'X-Auth-User': self.user_id,
            'X-Auth-Key': self.key
        }

        while True:
            resp, body = self.request('GET', auth_url, headers=headers)

            if resp.status == 200 or resp.status == 204:
                self.management_url = resp['x-server-management-url']
                self.auth_token = resp['x-auth-token']
                return
            elif resp.status == 305:
                redir_location = resp['location']
                redir_type, redir_hostname, auth_port, _ = self._split_in_parts(redir_location)
                auth_port = int(auth_port)
                if redir_hostname.startswith('127') or redir_hostname == 'localhost':
                    redir_hostname = auth_hostname
                auth_url = '%s://%s:%s%s' % (redir_type, redir_hostname, auth_port, auth_path)
                redirected = True
            else :
                #TODO check second port
                raise Exception("auth failed responce %s " % str(resp.status) )

        return None

    

    @staticmethod
    def _split_in_parts(url):
        type_, urlpath = urllib.splittype(url)
        host, path = urllib.splithost(urlpath)
        hostname, port = urllib.splitport(host)
        return type_, hostname, port, path