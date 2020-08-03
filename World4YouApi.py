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
    input_pos1 = 0
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
    pass


class Package:
    def __init__(self):
        self._package_id = None
        self._type = None
        self._domain = None
        self._resource_records = []

    @property
    def package_id(self) -> int:
        return self._package_id

    @property
    def type(self) -> str:
        return self._type

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def resource_records(self) -> List[ResourceRecord]:
        return self._resource_records.copy()


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
        r = requests.get(f'{API_URL}/dashboard/paketuebersicht', cookies=self.get_cookies())
        tbody_pos1 = r.text.find('<tbody>', r.text.find('<table id="paketTable"'))
        tbody_pos2 = r.text.find('</tbody>', tbody_pos1)
        table = r.text[tbody_pos1:tbody_pos2]

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

