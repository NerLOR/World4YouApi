#!/usr/bin/env python3.7

from __future__ import annotations
from typing import Dict

import re
import urllib.parse
import requests


class DnsApi:
    def __init__(self):
        self._resource_records = {}
        self._domains = []

    @property
    def domains(self):
        return self._domains

    @property
    def resource_records(self) -> Dict[int, ResourceRecord]:
        return self._resource_records

    def remove_domain_suffix(self, domain: str) -> str:
        for suffix in self.domains:
            if domain.endswith(suffix):
                return domain[:-len(suffix) - 1]
        return domain

    def resource_record(self, record_name: str, record_type: str, record_value: str) -> ResourceRecord or None:
        for rr_id, rr in self.resource_records.items():
            if rr.name == record_name \
                    and (record_value is None or rr.value == record_value) \
                    and (record_type is None or rr.type == record_type):
                return rr
        return None

    def add(self, record_name: str, record_type: str, record_value: str) -> None:
        pass

    def update(self, resource_record: ResourceRecord, new_record_value: str) -> None:
        pass

    def alter(self, resource_record: ResourceRecord, new_record_type: str, new_record_value: str = None) -> None:
        pass

    def delete(self, resource_record: ResourceRecord) -> None:
        pass


class ResourceRecord:
    def __init__(self, record_name: str, record_type: str, record_value: str, record_id: int, session: DnsApi = None):
        self._id = record_id
        self._name = record_name
        self._type = record_type
        self._value = record_value
        self._session = session

    @property
    def id(self) -> int:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def short_name(self) -> str:
        return self.session.remove_domain_suffix(self.name)

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> str:
        return self._value

    @property
    def session(self) -> DnsApi:
        if self._session is None:
            raise ReferenceError('Session has not been set')
        return self._session

    def update(self, new_record_value: str) -> None:
        self.session.update(self, new_record_value)

    def alter(self, new_record_type: str, new_record_value: str = None) -> None:
        self.session.alter(self, new_record_type, new_record_value)

    def delete(self) -> None:
        self.session.delete(self)

    def __str__(self) -> str:
        return f'{{{self.name}:{self.id}:{self.value}}}'


class World4YouApi(DnsApi):
    def __init__(self, domain: str = 'my.world4you.com', session_cookie_name: str = '__Host-W4Y_SESSID'):
        super().__init__()
        self._session_cookie = None
        self._session_cookie_name = session_cookie_name
        self._domain = domain
        self._logged_in = False
        self._unique_form_id = None
        self._package_id = None
        self._csrf_token = None

    @property
    def session_cookie(self) -> str:
        return self._session_cookie

    @property
    def session_cookie_name(self) -> str:
        return self._session_cookie_name

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def logged_in(self) -> bool:
        return self._logged_in

    @property
    def unique_form_id(self) -> str:
        return self._unique_form_id

    @property
    def package_id(self) -> str:
        return self._package_id

    @property
    def csrf_token(self) -> str:
        return self._csrf_token

    def _update_session(self, request: requests.models.Response) -> None:
        self._session_cookie = request.cookies[self.session_cookie_name]

    def _request(self, path: str, post: str = None, content_type: str = None) -> requests.Response:
        cookies = {self.session_cookie_name: self.session_cookie, 'csrf_token': self.csrf_token}
        headers = {'Content-Type': content_type, 'Referer': f'https://{self.domain}/dns/'}
        if not post:
            r = requests.get(f'https://{self.domain}{path}', cookies=cookies, headers=headers)
        else:
            r = requests.post(f'https://{self.domain}{path}', post, cookies=cookies, headers=headers)
        if r.status_code != 200:
            if r.status_code == 270:
                m = re.search(r'<div.*?id=message.*?>\s*(.*?)\s*</div>', r.text)
                msg = re.sub(r'<.*?>', '', m.group(1))
                msg = re.sub(r'\s+', ' ', msg)
                if msg[0] == ' ':
                    msg = msg[1:]
                raise ConnectionError(f'error: {msg}')
            else:
                raise ConnectionError(f'invalid status code: {str(r.status_code)} {str(r.reason)} ({str(r.url)})')
        self._update_session(r)
        return r

    def login(self, username: str, password: str) -> None:
        post = urllib.parse.urlencode({'customerid': username, 'password': password})
        try:
            r = self._request('/', post, 'application/x-www-form-urlencoded')
            self._logged_in = True
        except ConnectionError as e:
            raise ConnectionError(f'invalid credentials {str(e)}')
        m = re.search(r'Paket:.*?<strong>(.*?)</strong>', r.text)
        self._domains.append(m.group(1))

    def sync(self, response: requests.Response = None) -> None:
        if not self.logged_in:
            raise PermissionError('not logged in')
        elif response is None:
            r = self._request('/dns/')
        else:
            r = response
        form = re.search(r'<form.*?id="dns_form".*?>\s*(.*?)\s*</form>', r.text)
        m = re.search(r'<input.*?name="unique_form_id".*?value="(.*?)".*?/?>\s*'
                      r'<input.*?name="csrf_token".*?value="(.*?)".*?/?>\s*'
                      r'<input.*?name="package_id".*?value="(.*?)".*?/?>', form.group(1))
        self._unique_form_id = m.group(1)
        self._package_id = m.group(3)
        self._csrf_token = m.group(2)
        m = re.search(r'<table.*?class=".*?table_dns_other.*?".*?>.*?<tbody.*?>\s*(.*?)\s*</tbody>.*?</table>', r.text)
        self._resource_records = {}
        for row in re.finditer(r'<tr>\s*(.*?)\s*</tr>', m.group(1)):
            m = re.search(r'<td.*?>\s*(.*?)\s*</td>\s*'
                          r'<td.*?>\s*(.*?)\s*</td>\s*'
                          r'<td.*?>\s*<span.*?>.*?</span>\s*<div.*?>\s*<div.*?>\s*(.*?)\s*</div>\s*</div>\s*</td>\s*'
                          r'<td.*?>.*?<a.*?id="(.*?)".*?>.*?</a>\s*</td>', row.group(1))
            record_id = int(m.group(4))
            self._resource_records[record_id] = ResourceRecord(
                record_name=m.group(1),
                record_type=m.group(2),
                record_value=m.group(3),
                record_id=record_id,
                session=self
            )

    def add(self, record_name: str, record_type: str, record_value: str) -> None:
        if not self.logged_in:
            raise PermissionError('not logged in')
        post = urllib.parse.urlencode({
            'unique_form_id': self.unique_form_id,
            'package_id': self.package_id,
            'csrf_token': self.csrf_token,
            'action': 'add',
            'name': self.remove_domain_suffix(record_name),
            'type': record_type,
            'content': record_value
        })
        try:
            r = self._request('/dns/', post, 'application/x-www-form-urlencoded')
        except ConnectionError as e:
            raise ConnectionError(f'unable to add resource record: {str(e)}')
        self.sync(response=r)

    def update(self, resource_record: ResourceRecord, new_record_value: str) -> None:
        try:
            self.alter(resource_record, resource_record.type, new_record_value)
        except ConnectionError as e:
            raise ConnectionError('unable to update resource record: ' + str(e))

    def alter(self, resource_record: ResourceRecord, new_record_type: str, new_record_value: str = None) -> None:
        if not self.logged_in:
            raise PermissionError('not logged in')
        post = urllib.parse.urlencode({
            'unique_form_id': self.unique_form_id,
            'package_id': self.package_id,
            'csrf_token': self.csrf_token,
            'action': 'edit',
            'record_id': resource_record.id,
            'id': resource_record.id,
            'dns_name': resource_record.name,
            'dns_type': resource_record.type,
            'dns_value': new_record_value,
            'dns_name_orig': resource_record.name,
            'dns_type_orig': resource_record.type,
            'dns_value_orig': resource_record.value
        })
        try:
            r = self._request('/dns/', post, 'application/x-www-form-urlencoded')
        except ConnectionError as e:
            raise ConnectionError(f'unable to alter resource table: {str(e)}')
        self.sync(response=r)

    def delete(self, resource_record: ResourceRecord) -> None:
        if not self.logged_in:
            raise PermissionError('not logged in')
        post = urllib.parse.urlencode({
            'unique_form_id': self.unique_form_id,
            'package_id': self.package_id,
            'csrf_token': self.csrf_token,
            'action': 'delete',
            'record_id': resource_record.id,
        })
        try:
            r = self._request('/dns/', post, 'application/x-www-form-urlencoded')
        except ConnectionError as e:
            raise ConnectionError(f'unable to delete resource record: {str(e)}')
        self.sync(response=r)
