import base64
import hashlib
import logging
import string
import urllib2
import urlparse
import re
from collections import deque


class _NullHandler(logging.Handler):
    def emit(self, record):
        pass

__logger = logging.getLogger(__name__)
__logger.addHandler(_NullHandler())

try:
    # Separate module or Python <2.6
    import simplejson as json
    __logger.info("Using simplejson library")
except ImportError:
    # Python >=2.6
    import json
    __logger.info("Using native json library")


class ZabbixAPIException(Exception):
    """ generic zabbix api exception
    code list:
         -32602 - Invalid params (eg already exists)
         -32500 - no permissions
    """
    pass


class Already_Exists(ZabbixAPIException):
    pass


class InvalidProtoError(ZabbixAPIException):
    """ Recived an invalid proto """
    pass


class ZabbixAPI(object):
    __username__ = ''
    __password__ = ''

    auth = ''
    id = 0
    url = '/api_jsonrpc.php'
    params = None
    method = None
    # HTTP or HTTPS
    proto = 'http'
    # HTTP authentication
    httpuser = None
    httppasswd = None
    timeout = 10
    # sub-class instances.
    user = None
    usergroup = None
    host = None
    item = None
    hostgroup = None
    application = None
    trigger = None
    sysmap = None
    template = None
    drule = None

    # Constructor Params:
    # server: Server to connect to
    # path: Path leading to the zabbix install
    # proto: Protocol to use. http or https
    # We're going to use proto://server/path to find the JSON-RPC api.
    #
    # user: HTTP auth username
    # passwd: HTTP auth password
    # r_query_len: max len query history
    # **kwargs: Data to pass to each api module
    def __init__(self, server='http://localhost/zabbix', user=None,
                 passwd=None, timeout=10, r_query_len=10, **kwargs):
        """ Create an API object.  """

        self._setuplogging()

        self.server = server
        self.url = server + '/api_jsonrpc.php'
        self.proto = urlparse.urlparse(server).scheme
        self.logger.info("url: %s", self.url)

        self.httpuser = user
        self.httppasswd = passwd
        self.timeout = timeout

        self.usergroup = ZabbixAPIUserGroup(self, **kwargs)
        self.host = ZabbixAPIHost(self, **kwargs)
        self.item = ZabbixAPIItem(self, **kwargs)
        self.hostgroup = ZabbixAPIHostGroup(self, **kwargs)
        self.trigger = ZabbixAPITrigger(self, **kwargs)
        self.template = ZabbixAPITemplate(self, **kwargs)
        self.action = ZabbixAPIAction(self, **kwargs)
        self.id = 0
        self.r_query = deque([], maxlen=r_query_len)

    def _setuplogging(self):
        self.logger = logging.getLogger('{0}.{1}'.format(__name__,
            self.__class__.__name__))

    def set_log_level(self, level):
        self.logger.info("Set logging level to %s", level)
        self.logger.setLevel(level)

    def recent_query(self):
        """
        return recent query
        """
        return list(self.r_query)

    def json_obj(self, method, params={}):
        obj = {
            'jsonrpc': '2.0',
            'method':  method,
            'params':  params,
            'auth':    self.auth,
            'id':      self.id,
            }

        self.logger.debug("json_obj: %s", str(obj))

        return json.dumps(obj)

    def login(self, user='', password='', save=True):
        if user != '':
            l_user = user
            l_password = password

            if save:
                self.__username__ = user
                self.__password__ = password
        elif self.__username__ != '':
            l_user = self.__username__
            l_password = self.__password__
        else:
            raise ZabbixAPIException("No authentication information available")

        # don't log the raw password.
        hashed_pw_string = "md5(" + hashlib.md5(l_password).hexdigest() + ")"
        self.logger.debug("Trying to login with %s:%s", l_user,
            hashed_pw_string)

        obj = self.json_obj('user.authenticate', {'user': l_user,
                                                  'password': l_password})
        result = self.do_request(obj)
        self.auth = result['result']

    def test_login(self):
        if self.auth != '':
            obj = self.json_obj('user.checkAuthentication',
                {'sessionid': self.auth})
            result = self.do_request(obj)

            if not result['result']:
                self.auth = ''
                return False  # auth hash bad

            return True  # auth hash good
        else:
            return False

    def do_request(self, json_obj):
        headers = {'Content-Type': 'application/json-rpc',
                   'User-Agent': 'python/pyzabbix'}

        if self.httpuser:
            self.logger.debug("HTTP Auth enabled")
            auth = 'Basic ' + string.strip(base64.encodestring(self.httpuser +
                                                               ':' + self.httppasswd))
            headers['Authorization'] = auth
        self.r_query.append(str(json_obj))

        self.logger.info("Sending: %s", str(json_obj))
        self.logger.debug("Sending headers: %s", str(headers))

        request = urllib2.Request(url=self.url, data=json_obj, headers=headers)
        if self.proto == "https":
            https_handler = urllib2.HTTPSHandler(debuglevel=0)
            opener = urllib2.build_opener(https_handler)
        elif self.proto == "http":
            http_handler = urllib2.HTTPHandler(debuglevel=0)
            opener = urllib2.build_opener(http_handler)
        else:
            raise ZabbixAPIException("Unknown protocol %s" % self.proto)

        urllib2.install_opener(opener)
        response = opener.open(request, timeout=self.timeout)

        self.logger.debug("Response Code: %s", str(response.code))

        # NOTE: Getting a 412 response code means the headers are not in the
        # list of allowed headers.
        if response.code != 200:
            raise ZabbixAPIException("HTTP ERROR %s: %s"
                                     % (response.status, response.reason))
        reads = response.read()

        if len(reads) == 0:
            raise ZabbixAPIException("Received zero answer")
        try:
            jobj = json.loads(reads)
        except ValueError, msg:
            raise ZabbixAPIException("Unable to parse json: %s" % reads)
        self.logger.debug("Response Body: %s", str(jobj))

        self.id += 1

        if 'error' in jobj:  # some exception
            msg = "Error %s: %s, %s while sending %s" % (jobj['error']['code'],
                                                         jobj['error']['message'], jobj['error']['data'],
                                                         str(json_obj))
            if re.search(".*already\sexists.*", jobj["error"]["data"], re.I):
                raise Already_Exists(msg, jobj['error']['code'])
            else:
                raise ZabbixAPIException(msg, jobj['error']['code'])
        return jobj

    def logged_in(self):
        if self.auth != '':
            return True
        return False

    def api_version(self, **options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('APIInfo.version', options))
        return obj['result']

    def __checkauth__(self):
        if not self.logged_in():
            raise ZabbixAPIException("Not logged in.")


class ZabbixAPISubClass(ZabbixAPI):
    """ wrapper class to ensure all calls go through the parent object """
    parent = None

    def __init__(self, parent, **kwargs):
        self._setuplogging()
        self.logger.debug("Creating %s", self.__class__.__name__)

        self.parent = parent
        # Save any extra info passed in
        for key, val in kwargs.items():
            setattr(self, key, val)
            self.logger.warning("Set %s: %s", repr(key), repr(val))

    def __checkauth__(self):
        self.parent.__checkauth__()

    def do_request(self, req):
        return self.parent.do_request(req)

    def json_obj(self, method, param):
        return self.parent.json_obj(method, param)


def checkauth(fn):
    """ Decorator to check authentication of the decorated method """
    def ret(self, *args,**kwargs):
        self.__checkauth__()
        return fn(self, *args,**kwargs)
    return ret


def dojson(name):
    def decorator(fn):
        def wrapper(self, *args, **kwargs):
            arg=fn(self,*args,**kwargs)
            return self.do_request(self.json_obj(name, arg))['result']
        return wrapper
    return decorator


class ZabbixAPIHost(ZabbixAPISubClass):

    @dojson('host.get')
    @checkauth
    def get(self,extend=True, **opts):
        data={}
        if extend:
            data={'output':'extend'}
        return data

    @dojson('host.create')
    @checkauth
    def create(self,host,groups,ip,dns,templates=None,useip=1,port=10050,status=1, **opts):
        groups_=[{"groupid":i} for i in groups]
        templates_=[{"templateid":i} for i in templates]
        data={
            'host':host,
            "interfaces":
                [{
                     "type": 1,
                     "main": 1,
                     "useip": useip,
                     "ip": ip,
                     "dns": dns,
                     "port": port,
                     }],
            "groups": groups_,
            "templates": templates_,
            }
        return data

    @dojson('host.update')
    @checkauth
    def update(self, **opts):
        data={}
        if(opts.has_key('templates')):
            templates_=[{'templateid':i} for i in opts.get('templates')]
            opts['templates']=templates_
        if(opts.has_key('templates_clear')):
            templates_clear_=[{'templateid':i} for i in opts.get('templates_clear')]
            opts['templates_clear']=templates_clear_
        data.update(opts)
        return data

    @dojson('host.delete')
    @checkauth
    def delete(self, hostids,**opts):
        hostids_= [{"hostid": i} for i in hostids]
        return hostids_

    @dojson('host.exists')
    @checkauth
    def exists(self, host='',hostid='',nodeids=[],**opts):
        data={"host": host,'hostid':hostid,"nodeids": nodeids}
        return data


class ZabbixAPIItem(ZabbixAPISubClass):
    @dojson('item.get')
    @checkauth
    def get(self, **opts):
        return opts

    @dojson('item.getObjects')
    @checkauth
    def getObjects(self, **opts):
        return opts

    @dojson('item.create')
    @checkauth
    def create(self, **opts):
        return opts

    @dojson('item.update')
    @checkauth
    def update(self, **opts):
        return opts

    @dojson('item.delete')
    @checkauth
    def delete(self, **opts):
        return opts


class ZabbixAPIUserGroup(ZabbixAPISubClass):

    @dojson('usergroup.get')
    @checkauth
    def get(self, **opts):
        return opts

    @dojson('usergroup.create')
    @checkauth
    def create(self, **opts):
        return opts

    @dojson('usergroup.exists')
    @checkauth
    def exists(self, **opts):
        return opts

    @dojson('usergroup.massAdd')
    @checkauth
    def massAdd(self, **opts):
        return opts

    @dojson('usergroup.massRemove')
    @checkauth
    def massRemove(self, **opts):
        return opts

    @dojson('usergroup.massUpdate')
    @checkauth
    def massUpdate(self, **opts):
        return opts

    @dojson('usergroup.update')
    @checkauth
    def update(self, **opts):
        return opts

    @dojson('usergroup.delete')
    @checkauth
    def delete(self, **opts):
        pass


class ZabbixAPIHostGroup(ZabbixAPISubClass):

    @dojson('hostgroup.get')
    @checkauth
    def get(self,extend=True, **opts):
        data={}
        if extend:
            data={'output':'extend'}
        return data

    @dojson('hostgroup.create')
    @checkauth
    def create(self,name, **opts):
        return {"name": name},

    @dojson('hostgroup.update')
    @checkauth
    def update(self,host_group_id,name, **opts):
        data = {}
        data.update({
            "groupid": host_group_id,
            "name": name
        })
        data.update(data)

    @dojson('hostgroup.delete')
    @checkauth
    def delete(self,host_group_ids, **opts):
        return host_group_ids

    @dojson('hostgroup.exists')
    @checkauth
    def exists(self,name,nodeids=[], **opts):
        data={"name":name,"nodeids": nodeids}
        return opts


class ZabbixAPITrigger(ZabbixAPISubClass):

    @dojson('trigger.get')
    @checkauth
    def get(self, **opts):
        return opts

    @dojson('trigger.getObjects')
    @checkauth
    def getObjects(self, **opts):
        return opts

    @dojson('trigger.create')
    @checkauth
    def create(self, **opts):
        return opts

    @dojson('trigger.update')
    @checkauth
    def update(self, **opts):
        return opts

    @dojson('trigger.delete')
    @checkauth
    def delete(self, **opts):
        return opts

    @dojson('trigger.addDependencies')
    @checkauth
    def addDependencies(self, **opts):
        return opts

    @dojson('trigger.deleteDependencies')
    @checkauth
    def deleteDependencies(self, **opts):
        return opts


class ZabbixAPITemplate(ZabbixAPISubClass):

    @dojson('template.get')
    @checkauth
    def get(self,extend=True, **opts):
        data={}
        if extend:
            data={'output':'extend'}
        return data

    @dojson('template.create')
    @checkauth
    def create(self,name,groups,hosts=[], **opts):
        groups_=[{"groupid":i} for i in groups]
        hosts_ = [{"hostid":i} for i in hosts]
        data={
            "host":name,
            "groups": groups_,
            "hosts": hosts_
            }

        return data

    @dojson('template.update')
    @checkauth
    def update(self,templateid,name, **opts):
        data = {}
        data.update({
            "templateid": templateid,
            "name": name
        })
        data.update(data)

    @dojson('template.delete')
    @checkauth
    def delete(self,templateids, **opts):
        return templateids


class ZabbixAPIAction(ZabbixAPISubClass):
    @dojson('action.get')
    @checkauth
    def get(self, **opts):
        return opts

    @dojson('action.create')
    @checkauth
    def create(self, **opts):
        return opts

    @dojson('action.update')
    @checkauth
    def update(self, **opts):
        return opts

    @dojson('action.addConditions')
    @checkauth
    def addConditions(self, **opts):
        return opts

    @dojson('action.addOperations')
    @checkauth
    def addOperations(self, **opts):
        return opts

    @dojson('action.delete')
    @checkauth
    def delete(self, **opts):
        return opts

