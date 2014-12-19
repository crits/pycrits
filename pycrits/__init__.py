import json
import zipfile
import hashlib
import requests

from zipfile import ZipFile
from StringIO import StringIO

class pycritsFetchError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class pycrits(object):
    _API_VERSION       = '/api/v1/'
    _INDICATORS        = 'indicators/'
    _ACTORS            = 'actors/'
    _ACTOR_IDENTIFIERS = 'actoridentifiers/'
    _CAMPAIGNS         = 'campaigns/'
    _CERTIFICATES      = 'certificates/'
    _DOMAINS           = 'domains/'
    _EMAILS            = 'emails/'
    _EVENTS            = 'events/'
    _INDICATORS        = 'indicators/'
    _IPS               = 'ips/'
    _PCAPS             = 'pcaps/'
    _RAW_DATA          = 'raw_data/'
    _SAMPLES           = 'samples/'
    _SCREENSHOTS       = 'screenshots/'
    _TARGETS           = 'targets/'

    # POST only.
    _RELATIONSHIPS = 'relationships/'

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

    # Used for posting.
    def _post(self, url, params={}, files=None):
        params['username'] = self._username
        params['api_key'] = self._api_key
        url = self._base_url + url
        resp = requests.post(url, data=params, files=files, verify=self._verify)
        if resp.status_code != 200:
            raise pycritsFetchError("Response code: %s" % resp.status_code)

        try:
            results = json.loads(resp.text)
        except:
            raise pycritsFetchError("Unable to load JSON.")

        return results

    # Actually do the fetching.
    def _do_fetch(self, url, params={}):
        resp = requests.get(url, params=params, verify=self._verify)
        if resp.status_code != 200:
            raise pycritsFetchError("Response code: %s" % resp.status_code)

        try:
            results = json.loads(resp.text)
        except:
            raise pycritsFetchError("Unable to load JSON.")

        return results

    # Fetch and return once.
    def _single_fetch(self, url, params={}):
        params['username'] = self._username
        params['api_key'] = self._api_key
        url = self._base_url + url
        return self._do_fetch(url, params=params)

    # Fetch and yield a generator. Iterations will continue to fetch.
    def _fetch_generator(self, url, params={}):
        params['username'] = self._username
        params['api_key'] = self._api_key
        url = self._base_url + url

        next_ = True
        while next_:
            results = self._do_fetch(url, params)
            for obj in results['objects']:
                yield obj
            next_ = results['meta']['next']
            if next_:
                url = self._host + next_
                params = {}

    def actors(self, params={}):
        return self._fetch_generator(self._ACTORS, params)

    def actor_identifiers(self, params={}):
        return self._fetch_generator(self._ACTOR_IDENTIFIERS, params)

    def campaigns(self, params={}):
        return self._fetch_generator(self._CAMPAIGNS, params)

    def certificates(self, params={}):
        return self._fetch_generator(self._CERTIFICATES, params)

    def domains(self, params={}):
        return self._fetch_generator(self._DOMAINS, params)

    def emails(self, params={}):
        return self._fetch_generator(self._EMAILS, params)

    def events(self, params={}):
        return self._fetch_generator(self._EVENTS, params)

    def indicators(self, params={}):
        return self._fetch_generator(self._INDICATORS, params)

    def ips(self, params={}):
        return self._fetch_generator(self._IPS, params)

    def pcaps(self, params={}):
        return self._fetch_generator(self._PCAPS, params)

    def raw_datas(self, params={}):
        return self._fetch_generator(self._RAW_DATA, params)

    def samples(self, params={}):
        return self._fetch_generator(self._SAMPLES, params)

    def screenshots(self, params={}):
        return self._fetch_generator(self._SCREENSHOTS, params)

    def targets(self, params={}):
        return self._fetch_generator(self._TARGETS, params)

    # Fetch a single item given the ID.
    def actor(self, id_, params={}):
        return self._single_fetch(self._ACTORS + id_ + '/', params)

    def actor_identifier(self, id_, params={}):
        return self._single_fetch(self._ACTOR_IDENTIFIERS + id_ + '/', params)

    def campaign(self, id_, params={}):
        return self._single_fetch(self._CAMPAIGNS + id_ + '/', params)

    def certificate(self, id_, params={}):
        return self._single_fetch(self._CERTIFICATES + id_ + '/', params)

    def domain(self, id_, params={}):
        return self._single_fetch(self._DOMAINS + id_ + '/', params)

    def email(self, id_, params={}):
        return self._single_fetch(self._EMAILS + id_ + '/', params)

    def event(self, id_, params={}):
        return self._single_fetch(self._EVENTS + id_ + '/', params)

    def indicator(self, id_, params={}):
        return self._single_fetch(self._INDICATORS + id_ + '/', params)

    def ip(self, id_, params={}):
        return self._single_fetch(self._IPS + id_ + '/', params)

    def pcap(self, id_, params={}):
        return self._single_fetch(self._PCAPS + id_ + '/', params)

    def raw_data(self, id_, params={}):
        return self._single_fetch(self._RAW_DATA + id_ + '/', params)

    def sample(self, id_, params={}):
        return self._single_fetch(self._SAMPLES + id_ + '/', params)

    def screenshot(self, id_, params={}):
        return self._single_fetch(self._SCREENSHOTS + id_ + '/', params)

    def target(self, id_, params={}):
        return self._single_fetch(self._TARGETS + id_ + '/', params)

    # Fetch a campaign by name.
    def campaign_by_name(self, name, params={}):
        params['c-name'] = name
        results = self._single_fetch(self._CAMPAIGNS, params)
        return results['objects']

    # Force limit to 1 and only return _id.
    def _fetch_count(self, url, params={}):
        params['limit'] = 1
        params['only'] = 'id'
        results = self._single_fetch(url, params)
        return results['meta']['total_count']

    def indicator_count(self, params={}):
        return self._fetch_count(self._INDICATORS, params)

    def actor_count(self, params={}):
        return self._fetch_count(self._ACTORS, params)

    def actor_identifier_count(self, params={}):
        return self._fetch_count(self._ACTOR_IDENTIFIERS, params)

    def campaign_count(self, params={}):
        return self._fetch_count(self._CAMPAIGNS, params)

    def certificate_count(self, params={}):
        return self._fetch_count(self._CERTIFICATES, params)

    def domain_count(self, params={}):
        return self._fetch_count(self._DOMAINS, params)

    def email_count(self, params={}):
        return self._fetch_count(self._EMAILS, params)

    def event_count(self, params={}):
        return self._fetch_count(self._EVENTS, params)

    def indicator_count(self, params={}):
        return self._fetch_count(self._INDICATORS, params)

    def pcap_count(self, params={}):
        return self._fetch_count(self._PCAPS, params)

    def raw_data_count(self, params={}):
        return self._fetch_count(self._RAW_DATA, params)

    def sample_count(self, params={}):
        return self._fetch_count(self._SAMPLES, params)

    def screenshot_count(self, params={}):
        return self._fetch_count(self._SCREENSHOTS, params)

    def target_count(self, params={}):
        return self._fetch_count(self._TARGETS, params)

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

    # Helper to handle file uploads.
    # Take either a path to a file on disk or a file object.
    # If given both, the filepath will take precedence.
    # If we don't have a filename, use the md5 of the data.
    def _get_file_data(self, file_obj, filepath, filename):
        if not file_obj and not filepath:
            return None

        if filepath:
            file_obj = open(filepath, 'rb')

        if not filename:
            filename = hashlib.md5(file_obj.read()).hexdigest()
            file_obj.seek(0)

        return {'filedata': (filename, file_obj)}

    # Add objects to CRITs.
    def add_actor(self, name, source, params={}):
        params['name'] = name
        return self._post(self._ACTORS, params)

    def add_actor_identifier(self, id_type, id_, source, params={}):
        params['identifier_type'] = id_type
        params['identifier'] = id_
        params['source'] = source
        return self._post(self._ACTOR_IDENTIFIERS, params)

    def add_campaign(self, name, params={}):
        params['name'] = name
        return self._post(self._CAMPAIGNS, params)

    def add_certificate(self, source, file_obj=None, filepath=None,
                        filename=None, params={}):
        if not file_obj and not filepath:
            raise pycritsFetchError("Need a file object or filepath")

        files = self._get_file_data(file_obj, filepath, filename)

        params['source'] = source
        return self._post(self._CERTIFICATES, params, files=files)

    def add_domain(self, domain, source, params={}):
        params['domain'] = domain
        params['source'] = source
        return self._post(self._DOMAINS, params)

    def add_email(self, type_, source, file_obj=None, filepath=None,
                  filename=None, params={}):
        files = self._get_file_data(file_obj, filepath, filename)

        params['upload_type'] = type_
        params['source'] = source
        return self._post(self._EMAILS, params, files=files)

    def add_event(self, type_, title, description, source, params={}):
        params['event_type'] = type_
        params['title'] = title
        params['description'] = description
        params['source'] = source
        return self._post(self._EVENTS, params)

    def add_indicator(self, type_, value, source, params={}):
        params['type'] = type_
        params['value'] = value
        params['source'] = source
        return self._post(self._INDICATORS, params)

    def add_ip(self, ip, type_, source, params={}):
        params['source'] = source
        params['ip'] = ip
        params['ip_type'] = type_
        return self._post(self._IPS, params)

    def add_pcap(self, source, file_obj=None, filepath=None, filename=None,
                 params={}):
        if not file_obj and not filepath:
            raise pycritsFetchError("Need a file object or filepath")

        files = self._get_file_data(file_obj, filepath, filename)

        params['source'] = source
        return self._post(self._PCAPS, params, files=files)

    def add_raw_data(self, type_, title, data_type, source, data=None,
                     file_obj=None, filepath=None, filename=None, params={}):
        files = self._get_file_data(file_obj, filepath, filename)

        params['data'] = data
        params['upload_type'] = type_
        params['title'] = title
        params['data_type'] = data_type
        params['source'] = source
        return self._post(self._RAW_DATA, params, files=files)

    def add_sample(self, type_, source, file_obj=None, filepath=None,
                   filename=None, params={}):
        files = self._get_file_data(file_obj, filepath, filename)

        # Set filename so it is honored for metadata uploads too.
        params['upload_type'] = type_
        params['filename'] = filename
        params['source'] = source
        return self._post(self._SAMPLES, params, files=files)

    def add_screenshot(self, type_, oid, otype, source, file_obj=None,
                       filepath=None, filename=None, params={}):
        files = self._get_file_data(file_obj, filepath, filename)

        params['upload_type'] = type_
        params['oid'] = oid
        params['otype'] = otype
        params['source'] = source
        return self._post(self._SCREENSHOTS, params, files=files)

    def add_target(self, email, params={}):
        params['email_address'] = email
        return self._post(self._TARGETS, params)

    def add_relationship(self, left_type, left_id, right_type, right_id,
                         rel_type, params={}):
        params['left_type'] = left_type
        params['right_type'] = right_type
        params['left_id'] = left_id
        params['right_id'] = right_id
        params['rel_type'] = rel_type
        return self._post(self._RELATIONSHIPS, params)
