#!/usr/bin/python3

import requests
import re
import urllib.parse


class World4YouApi:
    def __init__(self, domain: str='my.world4you.com', session_cookie: str='__Host-W4Y_SESSID'):
        self._session = None
        self._session_cookie_name = session_cookie
        self._domain = domain
        self._logged_in = False
        self._resource_records = []

    @property
    def session(self):
        return self._session

    @property
    def session_cookie_name(self):
        return self._session_cookie_name

    @property
    def domain(self):
        return self._domain

    @property
    def logged_in(self):
        return self._logged_in

    @property
    def resource_records(self):
        return self._resource_records.copy()

    def _request(self, path: str, post: str=None, content_type: str=None):
        cookies = {self.session_cookie_name: self.session}
        if not post:
            r = requests.get("https://" + self.domain + path, cookies=cookies)
        else:
            r = requests.post("https://" + self.domain + path,
                              post,
                              cookies=cookies,
                              headers={'Content-Type': content_type})
        if r.status_code != 200:
            if r.status_code == 270:
                m = re.search(r'<div.*?id=message.*?>\s*(.*?)\s*</div>', r.text)
                msg = re.sub(r'<.*?>', '', m.group(1))
                msg = re.sub(r'\s+', ' ', msg)
                if msg[0] == ' ':
                    msg = msg[1:]
                raise ConnectionError('error: ' + msg)
            else:
                raise ConnectionError('invalid status code: ' +
                                      str(r.status_code) + ' ' + str(r.reason) + ' (' + str(r.url) + ')')
        self._update_session(r)
        return r

    def _update_session(self, request: requests.models.Response):
        self._session = request.cookies[self.session_cookie_name]
        return self.session

    def login(self, username: str, password: str):
        post = urllib.parse.urlencode({'username': username, 'password': password})
        try:
            self._request('/', post, 'application/x-www-form-urlencoded')
            self._logged_in = True
            return self.logged_in
        except ConnectionError:
            raise ConnectionError('invalid credentials')

    def get_resource_records(self):
        if not self.logged_in:
            raise PermissionError('not logged in')
        r = self._request('/dns/')
        m = re.search(r'<table.*?class=".*?table_dns_other.*?".*?>.*?<tbody.*?>\s*(.*?)\s*</tbody>.*?</table>', r.text)
        self._resource_records = []
        for row in re.finditer(r'<tr>\s*(.*?)\s*</tr>', m.group(1)):
            m = re.search(r'<td.*?>\s*(.*?)\s*</td>\s*'
                          r'<td.*?>\s*(.*?)\s*</td>\s*'
                          r'<td.*?>\s*<span.*?>.*?</span>\s*<div.*?>\s*<div.*?>\s*(.*?)\s*</div>\s*</div>\s*</td>\s*'
                          r'<td.*?>.*?<a.*?id="(.*?)".*?>.*?</a>\s*</td>', row.group(1))
            self._resource_records.append({
                'name': m.group(1),
                'type': m.group(2),
                'value': m.group(3),
                'id': m.group(4)
            })
        return self.resource_records

    def _get_unique_ids(self):
        if not self.logged_in:
            raise PermissionError('not logged in')
        r = self._request('/dns/')
        form = re.search(r'<form.*?id="dns_form".*?>\s*(.*?)\s*</form>', r.text)
        m = re.search(r'<input.*?name="unique_form_id".*?value="(.*?)".*?/?>\s*'
                      r'<input.*?name="package_id".*?value="(.*?)".*?/?>', form.group(1))
        unique_form_id = m.group(1)
        package_id = m.group(2)
        return unique_form_id, package_id

    def find_resource_record(self, resource_name: str):
        for rr in self.resource_records:
            if rr['name'] == resource_name:
                return rr.copy()
        return None

    def get_resource_record_index(self, resource_name: str):
        for rr in self.resource_records:
            if rr['name'] == resource_name:
                return self.resource_records.index(rr)
        return None

    def update(self, resource_name: str, new_value: str):
        try:
            self.alter(resource_name, self.find_resource_record(resource_name)['type'], new_value)
        except ConnectionError as e:
            raise ConnectionError('unable to update resource record: ' + str(e))
        return True

    def alter(self, resource_name: str, resource_type: str, new_value: str=None):
        if not self.logged_in:
            raise PermissionError('not logged in')
        resource_record = self.find_resource_record(resource_name)
        rr_index = self.get_resource_record_index(resource_name)
        if not resource_record:
            raise IndexError('resource record not found')
        unique_form_id, package_id = self._get_unique_ids()
        post = urllib.parse.urlencode({
            'unique_form_id': unique_form_id,
            'package_id': package_id,
            'action': 'edit',
            'record_id': resource_record['id'],
            'id': resource_record['id'],
            'dns_name': resource_record['name'],
            'dns_type': resource_type,
            'dns_value': new_value,
            'dns_name_orig': resource_record['name'],
            'dns_type_orig': resource_record['type'],
            'dns_value_orig': resource_record['value']
        })
        try:
            self._request('/dns/', post, 'application/x-www-form-urlencoded')
        except ConnectionError as e:
            raise ConnectionError('unable to alter resource table: ' + str(e))
        self._resource_records[rr_index]['type'] = resource_type
        self._resource_records[rr_index]['value'] = new_value
        return True

    def delete(self, resource_name: str):
        if not self.logged_in:
            raise PermissionError('not logged in')
        resource_record = self.find_resource_record(resource_name)
        rr_index = self.get_resource_record_index(resource_name)
        if not resource_record:
            raise IndexError('resource record not found')
        unique_form_id, package_id = self._get_unique_ids()
        post = urllib.parse.urlencode({
            'unique_form_id': unique_form_id,
            'package_id': package_id,
            'action': 'delete',
            'record_id': resource_record['id'],
        })
        try:
            self._request('/dns/', post, 'application/x-www-form-urlencoded')
        except ConnectionError as e:
            raise ConnectionError('unable to delete resource record: ' + str(e))
        self._resource_records.remove(self._resource_records[rr_index])
        return True

    def add(self, resource_name: str, resource_type: str, value: str):
        if not self.logged_in:
            raise PermissionError('not logged in')
        unique_form_id, package_id = self._get_unique_ids()
        post = urllib.parse.urlencode({
            'unique_form_id': unique_form_id,
            'package_id': package_id,
            'action': 'add',
            'name': resource_name,
            'type': resource_type,
            'content': value
        })
        try:
            self._request('/dns/', post, 'application/x-www-form-urlencoded')
        except ConnectionError as e:
            raise ConnectionError('unable to add resource record: ' + str(e))
        self.get_resource_records()
        return True

