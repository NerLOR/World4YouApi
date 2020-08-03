#!/usr/bin/env python3

from __future__ import annotations
from typing import Dict, List
import requests
import re
import json
import sys
import base64


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
    def __init__(self, rr_type: str, fqdn: str, value: str, priority: int = None):
        self._type = rr_type.upper()
        self._fqdn = fqdn.lower()
        self._value = value
        self._priority = priority

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
    def priority(self) -> int:
        return self._priority

    @property
    def id(self) -> str:
        return base64.b64encode(self.__str__()).decode('ascii')

    def __str__(self) -> str:
        return f'{self.type}:{str(self.priority) + " " if self.priority is not None else ""}{self.fqdn}.:{self.value}'

    def __repr__(self) -> str:
        return f'<ResourceRecord{{{self.__str__()}}}>'


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
                                                   rr['prio'] if len(rr['prio']) > 0 else None))
        return package._resource_records

    def get_package_by_domain(self, domain: str) -> Package:
        for p in self.packages:
            if p.domain == domain:
                return p
        raise KeyError(f'Package with domain \'{domain}\' can not be found')

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


if __name__ == '__main__':
    api = MyWorld4You()
    print(api.login(sys.argv[1], sys.argv[2]))
    print(api.packages)
    print(api.get_package_by_domain('project-argos.at').resource_records)
