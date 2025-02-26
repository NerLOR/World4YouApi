#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import requests
import re
import json


API_URL = 'https://my.world4you.com/en'
KEY_VALUE = re.compile(r'([^=\s<>]+)(="([^"]*)")?')
HTML_TAG = re.compile(r'<[^>]*>')
SPACES = re.compile(r'[ \t]+')


def parse_form(page: str, pre: str = '<form', post: str = '</form>') -> dict[str, dict[str, str]]:
    pos1 = page.find(pre)
    pos2 = page.find(post, pos1)
    form = page[pos1:pos2]
    inputs = {}
    input_pos2 = 0
    while True:
        input_pos1 = form.find('<input', input_pos2)
        if input_pos1 < 0:
            break
        input_pos2 = form.find('>', input_pos1)
        input_elem = form[input_pos1:input_pos2 + 1]
        input_obj = {}
        for kv in KEY_VALUE.finditer(input_elem[6:]):
            key = kv.group(1)
            value = kv.group(3)
            if key == 'name':
                inputs[value] = input_obj
            elif key in ('value', 'type') and len(value) > 0:
                input_obj[key] = value
            elif key == 'required':
                input_obj[key] = True
    return inputs


def get_csrf_token(page: str) -> str:
    pos1 = page.find('<meta name="csrf-token"')
    pos2 = page.find('>', pos1)
    meta = page[pos1:pos2 + 1]
    for kv in KEY_VALUE.finditer(meta[5:]):
        key = kv.group(1)
        value = kv.group(3)
        if key == 'content':
            return value


def get_form_error_message(page: str) -> str or None:
    start = '<div class="form-error-message">'
    stop = '</div>'

    pos1 = page.find(start)
    if pos1 == -1:
        return None

    pos2 = page.find(stop, pos1 + len(start))
    if pos2 == -1:
        return None

    msg = page[pos1 + len(start):pos2]
    msg = re.sub(r'\s+', ' ', re.sub(r'<[^>]*>', ' ', msg)).strip()

    return msg


class ResourceRecord:
    def __init__(self, rr_type: str, fqdn: str, value: str, prio: int = None, rr_id: str = None):
        self._type = rr_type.upper()
        self._fqdn = fqdn.lower()
        self._value = value
        self._prio = prio
        self._id = rr_id

    @property
    def type(self) -> str:
        return self._type

    @property
    def fqdn(self) -> str:
        return self._fqdn

    @property
    def value(self) -> str:
        return self._value

    @property
    def prio(self) -> int:
        return self._prio

    @property
    def id(self) -> str:
        return self._id

    def __str__(self) -> str:
        return f'<ResourceRecord{{{self.type}:{str(self.prio) + " " if self.prio is not None else ""}{self.fqdn}:{self.value}}}>'

    def __repr__(self) -> str:
        return self.__str__()


class Package:
    def __init__(self, session: MyWorld4You, package_id: int, domain: str, package_type: str):
        self._session = session
        self._id = package_id
        self._type = package_type
        self._domain = domain
        self._resource_records = None

    @property
    def id(self) -> int:
        return self._id

    @property
    def type(self) -> str:
        return self._type

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def resource_records(self) -> list[ResourceRecord]:
        if self._resource_records is None:
            self.load_resource_records()
        return self._resource_records.copy()

    def mark_dirty(self):
        self._resource_records = None

    def load_resource_records(self) -> list[ResourceRecord]:
        if self not in self._session._packages:
            raise KeyError(f'Can not load resource records from foreign package')

        r = self._session.get(f'/{self.id}/dns')
        pos1 = r.text.find('<meta id="currentDns"')
        pos2 = r.text.find('>', pos1)
        meta = r.text[pos1:pos2]

        data_records = []
        for kv in KEY_VALUE.finditer(meta[21:]):
            key = kv.group(1)
            value = kv.group(3)
            if key == 'data-records':
                data_records = json.loads(value.replace('&quot;', '"'))
        if self._resource_records is None:
            self._resource_records = []
        else:
            self._resource_records.clear()
        for rr in data_records:
            self._resource_records.append(
                ResourceRecord(rr['type'],
                               rr['name'],
                               rr['value'],
                               rr['prio'] if len(rr['prio']) > 0 else None,
                               rr['id']))
        return self._resource_records

    def __str__(self) -> str:
        return f'<Package#{self.id}{{{self.domain}/{self.type}/#{len(self.resource_records)}}}>'

    def __repr__(self) -> str:
        return self.__str__()


class MyWorld4You:
    def __init__(self):
        self._session = requests.session()
        self._customer_id = None
        self._packages = []

    def get(self, path: str) -> requests.Response:
        return self._session.get(f'{API_URL}{path}')

    def post(self, path: str, data, allow_redirects: bool = True) -> requests.Response:
        return self._session.post(f'{API_URL}{path}', data, headers={'X-Requested-With': 'XMLHttpRequest'},
                                  allow_redirects=allow_redirects)

    def login(self, user_nr: int, password: str) -> bool:
        r = self.get('/login')
        inputs = parse_form(r.text, f'<form action="{API_URL}/login" id="loginForm"')

        r = self.post('/login', {
            '_username': str(user_nr),
            '_password': str(password),
            '_csrf_token': inputs['_csrf_token']['value']
        })
        res = json.loads(r.text)

        if r.status_code == 200 and res['success']:
            self._customer_id = user_nr
            self.load_packages()
            return True
        else:
            raise PermissionError(f'{r.status_code} {r.reason}' + (f': {res["message"]}' if res['message'] is not None else ''))

    def load_packages(self) -> list[Package]:
        self._packages.clear()
        r = self.get('/')

        script_p1 = r.text.find('id="paketListData"')
        if script_p1 == -1:
            raise RuntimeError()
        script_p1 = r.text.find('>', script_p1)
        if script_p1 == -1:
            raise RuntimeError()
        script_p2 = r.text.find('</script>', script_p1)
        if script_p2 == -1:
            raise RuntimeError()

        items = json.loads(r.text[script_p1 + 1:script_p2])['items']
        for item in items:
            package = Package(self, item['id'], item['fqdn'], item['description'])
            self._packages.append(package)
        return self.packages

    def get_package_by_domain(self, domain: str) -> Package:
        for p in self.packages:
            if p.domain == domain:
                return p
        raise KeyError(f'Package with domain \'{domain}\' can not be found')

    def get_package_by_fqdn(self, fqdn: str) -> Package:
        for p in self.packages:
            if fqdn.endswith('.' + p.domain) or fqdn == p.domain:
                return p

    def get_resource_record(self, fqdn: str, rr_type: str = None, value: str = None,
                            prio: int = None) -> ResourceRecord:
        return self.get_resource_records(fqdn, rr_type, value, prio, force_one=True, force_all=False)[0]

    def get_resource_records(self, fqdn: str, rr_type: str = None, value: str = None, prio: int = None,
                             force_one: bool = False, force_all: bool = True) -> list[ResourceRecord]:
        matches = self.find_resource_records(fqdn, rr_type, value, prio)
        if len(matches) == 0:
            raise KeyError('No resource record may be found')
        elif len(matches) > 1:
            if force_one:
                return matches[:1]
            elif not force_all:
                raise KeyError('Multiple resource records were found')
        return matches

    def find_resource_records(self, fqdn: str, rr_type: str = None, value: str = None,
                              prio: int = None) -> list[ResourceRecord]:
        matches = []
        for p in self.packages:
            for rr in p.resource_records:
                if rr.fqdn == fqdn \
                        and (rr_type is None or rr_type == rr.type) \
                        and (value is None or value == rr.value) \
                        and (prio is None or prio == rr.prio):
                    matches.append(rr)
        return matches

    def update_resource_record(self, resource_record: ResourceRecord, new_value: str = None, new_fqdn: str = None,
                               new_type: str = None, new_prio: int = None) -> bool:
        package = self.get_package_by_fqdn(resource_record.fqdn)
        r = self.get(f'/{package.id}/dns')
        inputs = parse_form(r.text, '<form name="EditDnsRecordForm"', '</form>')

        r = self.post(f'/{package.id}/dns', {
            'EditDnsRecordForm[name]': (new_fqdn or resource_record.fqdn)[:-len(package.domain) - 1],
            'EditDnsRecordForm[dnsType][type]': new_type or resource_record.type,
            'EditDnsRecordForm[dnsType][prio]': new_prio or resource_record.prio,
            'EditDnsRecordForm[value]': new_value or resource_record.value,
            'EditDnsRecordForm[id]': resource_record.id,
            'EditDnsRecordForm[uniqueFormIdDP]': inputs['EditDnsRecordForm[uniqueFormIdDP]']['value'],
            'EditDnsRecordForm[_token]': inputs['EditDnsRecordForm[_token]']['value']
        }, allow_redirects=False)

        if r.status_code == 302:
            package.mark_dirty()
            return True
        elif r.status_code == 500:
            raise RuntimeError('Invalid input')
        elif r.status_code == 200:
            msg = get_form_error_message(r.text)
            raise RuntimeError(msg)
        else:
            raise RuntimeError(f'Unknown error: {r.status_code} {r.reason}')

    def delete_resource_record(self, resource_record: ResourceRecord) -> bool:
        package = self.get_package_by_fqdn(resource_record.fqdn)
        r = self.get(f'/{package.id}/dns')
        inputs = parse_form(r.text, '<form name="DeleteDnsRecordForm"', '</form>')

        r = self.post(f'/{package.id}/dns/record/delete', {
            'DeleteDnsRecordForm[id]': resource_record.id,
            'DeleteDnsRecordForm[uniqueFormIdDP]': inputs['DeleteDnsRecordForm[uniqueFormIdDP]']['value'],
            'DeleteDnsRecordForm[_token]': inputs['DeleteDnsRecordForm[_token]']['value']
        }, allow_redirects=False)

        if r.status_code == 302:
            package.mark_dirty()
            return True
        elif r.status_code == 500:
            raise RuntimeError('Invalid input')
        elif r.status_code == 200:
            msg = get_form_error_message(r.text)
            raise RuntimeError(msg)
        else:
            raise RuntimeError(f'Unknown error: {r.status_code} {r.reason}')

    def add_resource_record(self, rr_type: str, fqdn: str, value: str, prio: int = None) -> bool:
        package = self.get_package_by_fqdn(fqdn)
        r = self.get(f'/{package.id}/dns')
        inputs = parse_form(r.text, '<form name="AddDnsRecordForm"', '</form>')

        r = self.post(f'/{package.id}/dns', {
            'AddDnsRecordForm[name]': fqdn[:-len(package.domain) - 1],
            'AddDnsRecordForm[dnsType][type]': str(rr_type),
            'AddDnsRecordForm[dnsType][prio]': str(prio) if prio is not None else '',
            'AddDnsRecordForm[value]': str(value),
            'AddDnsRecordForm[uniqueFormIdDP]': inputs['AddDnsRecordForm[uniqueFormIdDP]']['value'],
            'AddDnsRecordForm[_token]': inputs['AddDnsRecordForm[_token]']['value']
        }, allow_redirects=False)

        if r.status_code == 302:
            package.mark_dirty()
            return True
        elif r.status_code == 500:
            raise RuntimeError('Invalid input')
        elif r.status_code == 200:
            msg = get_form_error_message(r.text)
            raise RuntimeError(msg)
        else:
            raise RuntimeError(f'Unknown error: {r.status_code} {r.reason}')

    @property
    def customer_id(self) -> str:
        return self._customer_id

    @property
    def packages(self) -> list[Package]:
        return self._packages.copy()
