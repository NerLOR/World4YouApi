#!/usr/bin/env python3

from __future__ import annotations
from typing import Dict, List
import requests
import re
import json
import sys


API_URL = 'https://my.world4you.com/en'
KEY_VALUE = re.compile(r'([^=\s<>]+)(="([^"]*)")?')


def parse_form(page: str, pre: str = '<form', post: str = '</form>') -> Dict[str, Dict[str, str]]:
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
    def __init__(self, package_id: int, domain: str, package_type: str):
        self._id = package_id
        self._type = package_type
        self._domain = domain
        self._resource_records = []

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
    def resource_records(self) -> List[ResourceRecord]:
        return self._resource_records.copy()

    def __str__(self) -> str:
        return f'<Package#{self.id}{{{self.domain}/{self.type}/#{len(self.resource_records)}}}>'

    def __repr__(self) -> str:
        return self.__str__()


class MyWorld4You:
    def __init__(self):
        self._session_id = None
        self._customer_id = None
        self._packages = []

    def login(self, user_nr: int, password: str) -> bool:
        r = requests.get(f'{API_URL}/login')
        self._session_id = r.cookies['W4YSESSID']
        inputs = parse_form(r.text, f'<form action="{API_URL}/login" id="loginForm"')
        r = requests.post(f'{API_URL}/login', {
            '_username': str(user_nr),
            '_password': str(password),
            '_csrf_token': inputs['_csrf_token']['value']
        }, cookies=self.get_cookies(), headers={'X-Requested-With': 'XMLHttpRequest'})
        res = json.loads(r.text)
        if r.status_code == 200 and res['success']:
            self._session_id = r.cookies['W4YSESSID']
            self._customer_id = user_nr
            self.load_packages()
            return True
        else:
            if res['message'] is not None:
                print(f'{r.status_code} {r.reason}: {res["message"]}', file=sys.stderr)
            else:
                print(f'{r.status_code} {r.reason}', file=sys.stderr)
            return False

    def load_packages(self) -> List[Package]:
        self._packages.clear()
        r = requests.get(f'{API_URL}/dashboard/paketuebersicht', cookies=self.get_cookies())
        tbody_pos1 = r.text.find('<tbody>', r.text.find('<table id="paketTable"'))
        tbody_pos2 = r.text.find('</tbody>', tbody_pos1)
        table = r.text[tbody_pos1:tbody_pos2]
        tr_pos_end = 0
        while True:
            tr_pos_start = table.find('<tr', tr_pos_end)
            if tr_pos_start < 0:
                break
            tr_pos_end = table.find('</tr>', tr_pos_start)
            tr = table[tr_pos_start:tr_pos_end]
            td_pos_end = 0
            p_type, p_id, p_domain = None, None, None
            for i in range(3):
                td_pos_start = tr.find('<td', td_pos_end)
                if td_pos_start < 0:
                    break
                td_pos_end = tr.find('</td>', td_pos_start)
                td = re.sub(r'\s+', ' ', re.sub(r'<[^>]*>', ' ', tr[td_pos_start:td_pos_end])).strip()
                if i == 0:
                    p_type = td
                elif i == 1:
                    p_id = int(td)
                elif i == 2:
                    p_domain = td
            package = Package(p_id, p_domain, p_type)
            self._packages.append(package)
            self.load_resource_records(package)
        return self.packages

    def load_resource_records(self, package: Package) -> List[ResourceRecord]:
        if package not in self._packages:
            raise KeyError(f'Can not load resource records from foreign package')
        r = requests.get(f'{API_URL}/{package.id}/dns', cookies=self.get_cookies())
        pos1 = r.text.find('<meta id="currentDns"')
        pos2 = r.text.find('>', pos1)
        meta = r.text[pos1:pos2]
        data_records = []
        for kv in KEY_VALUE.finditer(meta[21:]):
            key = kv.group(1)
            value = kv.group(3)
            if key == 'data-records':
                data_records = json.loads(value.replace('&quot;', '"'))
        package._resource_records.clear()
        for rr in data_records:
            package._resource_records.append(ResourceRecord(rr['type'],
                                             rr['name'],
                                             rr['value'],
                                             rr['prio'] if len(rr['prio']) > 0 else None,
                                             rr['id']))
        return package._resource_records

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
        matches = self.get_resource_records(fqdn, rr_type, value, prio)
        if len(matches) == 0:
            raise KeyError('No resource record can be found')
        elif len(matches) > 1:
            raise KeyError('Multiple resource records were found')
        else:
            return matches[0]

    def get_resource_records(self, fqdn: str, rr_type: str = None, value: str = None,
                             prio: int = None) -> List[ResourceRecord]:
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
        r = requests.get(f'{API_URL}/{package.id}/dns', cookies=self.get_cookies())
        inputs = parse_form(r.text, '<form name="EditDnsRecordForm"', '</form>')

        r = requests.post(f'{API_URL}/{package.id}/dns', {
            'EditDnsRecordForm[name]': (new_fqdn or resource_record.fqdn)[:-len(package.domain) - 1],
            'EditDnsRecordForm[dnsType][type]': new_type or resource_record.type,
            'EditDnsRecordForm[dnsType][prio]': new_prio or resource_record.prio,
            'EditDnsRecordForm[value]': new_value or resource_record.value,
            'EditDnsRecordForm[id]': resource_record.id,
            'EditDnsRecordForm[aktivPaket]': str(package.id),
            'EditDnsRecordForm[uniqueFormIdDP]': inputs['EditDnsRecordForm[uniqueFormIdDP]']['value'],
            'EditDnsRecordForm[uniqueFormIdTTL]': inputs['EditDnsRecordForm[uniqueFormIdTTL]']['value'],
            'EditDnsRecordForm[_token]': inputs['EditDnsRecordForm[_token]']['value']
        }, cookies=self.get_cookies(), allow_redirects=False)

        if r.status_code == 302:
            self.load_packages()
            return True
        else:
            return False

    def delete_resource_record(self, resource_record: ResourceRecord) -> bool:
        package = self.get_package_by_fqdn(resource_record.fqdn)
        r = requests.get(f'{API_URL}/{package.id}/dns', cookies=self.get_cookies())
        inputs = parse_form(r.text, '<form name="DeleteDnsRecordForm"', '</form>')

        r = requests.post(f'{API_URL}/{package.id}/deleteRecord', {
            'DeleteDnsRecordForm[recordId]': resource_record.id,
            'DeleteDnsRecordForm[aktivPaket]': str(package.id),
            'DeleteDnsRecordForm[uniqueFormIdDP]': inputs['DeleteDnsRecordForm[uniqueFormIdDP]']['value'],
            'DeleteDnsRecordForm[uniqueFormIdTTL]': inputs['DeleteDnsRecordForm[uniqueFormIdTTL]']['value'],
            'DeleteDnsRecordForm[_token]': inputs['DeleteDnsRecordForm[_token]']['value']
        }, cookies=self.get_cookies(), allow_redirects=False)

        if r.status_code == 302:
            self.load_packages()
            return True
        else:
            return False

    def add_resource_record(self, rr_type: str, fqdn: str, value: str, prio: int = None) -> bool:
        package = self.get_package_by_fqdn(fqdn)
        r = requests.get(f'{API_URL}/{package.id}/dns', cookies=self.get_cookies())
        inputs = parse_form(r.text, '<form name="AddDnsRecordForm"', '</form>')

        r = requests.post(f'{API_URL}/{package.id}/dns', {
            'AddDnsRecordForm[name]': fqdn.split()[:-len(package.domain) - 1],
            'AddDnsRecordForm[dnsType][type]': str(rr_type),
            'AddDnsRecordForm[dnsType][prio]': str(prio) if prio is not None else '',
            'AddDnsRecordForm[value]': str(value),
            'AddDnsRecordForm[aktivPaket]': str(package.id),
            'AddDnsRecordForm[uniqueFormIdDP]': inputs['AddDnsRecordForm[uniqueFormIdDP]']['value'],
            'AddDnsRecordForm[uniqueFormIdTTL]': inputs['AddDnsRecordForm[uniqueFormIdTTL]']['value'],
            'AddDnsRecordForm[_token]': inputs['AddDnsRecordForm[_token]']['value']
        }, cookies=self.get_cookies(), allow_redirects=False)

        if r.status_code == 302:
            self.load_packages()
            return True
        elif r.status_code == 500:
            print(f'Error: Invalid input', file=sys.stderr)
            return False
        else:
            pos1 = r.text.find('<span class="form-error-message">')
            pos2 = r.text.find('</span>', pos1)
            msg = re.sub(r'\s+', ' ', re.sub(r'<[^>]*>', ' ', r.text[pos1:pos2])).strip()
            print(f'Error: {msg}', file=sys.stderr)
            return False

    def get_cookies(self) -> Dict[str, str]:
        return {'W4YSESSID': self.session_id}

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def customer_id(self) -> str:
        return self._customer_id

    @property
    def packages(self) -> List[Package]:
        return self._packages.copy()
