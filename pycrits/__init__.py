import json
import zipfile
import requests

from zipfile import ZipFile
from StringIO import StringIO

class pycritsFetchError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class pycrits(object):
    # XXX: Currently only supports GETs. This means not all API endpoints are
    # supported.
    _API_VERSION = '/api/v1/'
    _INDICATORS = 'indicators/'
    _ACTORS = 'actors/'
    _ACTOR_IDENTIFIERS = 'actoridentifiers/'
    _CAMPAIGNS = 'campaigns/'
    _CERTIFICATES = 'certificates/'
    _DOMAINS = 'domains/'
    _EMAILS = 'emails/'
    _EVENTS = 'events/'
    _INDICATORS = 'indicators/'
    _PCAPS = 'pcaps/'
    _RAW_DATA = 'raw_data/'
    _SAMPLES = 'samples/'
    _SCREENSHOTS = 'screenshots/'
    _TARGETS = 'targets/'

    # The password for zip files.
    _PASSWORD = 'infected'

    def __init__(self, host, username, api_key):
        self._base_url = host + self._API_VERSION
        self._host = host
        self._username = username
        self._api_key = api_key
        self._verify = True

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value
        self._base_url = value + self._API_VERSION

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        return self_username

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, value):
        self._api_key = value

    @property
    def verify(self):
        return self._verify

    @verify.setter
    def verify(self, value):
        self._verify = bool(value)

    def _fetch(self, url, params={}):
        params['username'] = self._username
        params['api_key'] = self._api_key
        url = self._base_url + url

        next_ = True
        while next_:
            resp = requests.get(url, params=params, verify=self._verify)
            if resp.status_code != 200:
                raise pycritsFetchError("Response code: %s" % resp.status_code)

            try:
                results = json.loads(resp.text)
            except:
                raise pycritsFetchError("Unable to load JSON.")
            yield results
            next_ = results['meta']['next']
            if next_:
                url = self._host + next_
                params={}

    def indicators(self, params={}):
        return self._fetch(self._INDICATORS, params)

    def actors(self, params={}):
        return self._fetch(self._ACTORS, params)

    def actor_identifiers(self, params={}):
        return self._fetch(self._ACTOR_IDENTIFIERS, params)

    def campaigns(self, params={}):
        return self._fetch(self._CAMPAIGNS, params)

    def certificates(self, params={}):
        return self._fetch(self._CERTIFICATES, params)

    def domains(self, params={}):
        return self._fetch(self._DOMAINS, params)

    def emails(self, params={}):
        return self._fetch(self._EMAILS, params)

    def events(self, params={}):
        return self._fetch(self._EVENTS, params)

    def indicators(self, params={}):
        return self._fetch(self._INDICATORS, params)

    def pcaps(self, params={}):
        return self._fetch(self._PCAPS, params)

    def raw_data(self, params={}):
        return self._fetch(self._RAW_DATA, params)

    def samples(self, params={}):
        return self._fetch(self._SAMPLES, params)

    def screenshots(self, params={}):
        return self._fetch(self._SCREENSHOTS, params)

    def targets(self, params={}):
        return self._fetch(self._TARGETS, params)

    def _fetch_binary(self, url, id_=None, params={}):
        params['username'] = self._username
        params['api_key'] = self._api_key
        params['file'] = 1
        url = self._base_url + url
        if id_:
            url += id_ + '/'

        resp = requests.get(url, params=params, verify=self._verify)
        if resp.status_code != 200:
            raise pycritsFetchError("Response code: %s" % resp.status_code)

        return StringIO(resp.content)

    # If not a zip file (ie: "No files found") just return an empty list.
    def _unzip_file(self, file_):
        results = []
        if not zipfile.is_zipfile(file_):
            return results

        try:
            zf = ZipFile(file_, 'r')
            filelist = zf.infolist()

            for fileentry in filelist:
                unzipped_file = zf.open(fileentry, pwd=self._PASSWORD).read()
                results.append({'filename': fileentry.filename,
                                'data': unzipped_file})
        except Exception as e:
            zf.close()
            file_.close()
            raise

        zf.close()
        file_.close()
        return results

    def fetch_sample(self, md5=None, sha256=None, id_=None, params={}):
        if md5:
            params['c-md5'] = md5
            file_ = self._fetch_binary(self._SAMPLES, params=params)
        elif sha256:
            params['c-sha256'] = sha256
            file_ = self._fetch_binary(self._SAMPLES, params=params)
        elif id_:
            file_ = self._fetch_binary(self._SAMPLES, id_=id_, params=params)
        else:
            file_ = self._fetch_binary(self._SAMPLES, params=params)
        return self._unzip_file(file_)

    def fetch_pcap(self, md5=None, id_=None, params={}):
        if md5:
            params['c-md5'] = md5
            file_ = self._fetch_binary(self._PCAPS, params=params)
        elif id_:
            file_ = self._fetch_binary(self._PCAPS, id_=id_, params=params)
        else:
            file_ = self._fetch_binary(self._PCAPS, params=params)
        return self._unzip_file(file_)
