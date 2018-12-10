#!/bin/sh

SCRIPTPATH='../'

# Usage: add  _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
# Used to add txt record
dns_w4yapi_add() {
    FQDN="$1"
    TXT_VALUE="$2"

    W4Y_USERNAME="${W4Y_USERNAME:-$(_readaccountconf_mutable W4Y_USERNAME)}"
    W4Y_PASSWORD="${W4Y_PASSWORD:-$(_readaccountconf_mutable W4Y_PASSWORD)}"
    if [ -z "$W4Y_USERNAME" ] || [ -z "$W4Y_PASSWORD" ]; then
        W4Y_USERNAME=""
        W4Y_PASSWORD=""
        _err "You don't specified world4you username and password yet."
        _err "Please create you key and try again."
        return 1
    fi

    _saveaccountconf_mutable W4Y_USERNAME "$W4Y_USERNAME"
    _saveaccountconf_mutable W4Y_PASSWORD "$W4Y_PASSWORD"

    ${SCRIPTPATH}world4you -u "$W4Y_USERNAME" -p "$W4Y_PASSWORD" add "$FQDN" TXT "$TXT_VALUE"
}

# Usage: fulldomain txtvalue
# Used to remove the txt record after validation
dns_w4yapi_rm() {
    FQDN="$1"
    TXT_VALUE="$2"
    ${SCRIPTPATH}world4you -u "$W4Y_USERNAME" -p "$W4Y_PASSWORD" delete "$FQDN" TXT "$TXT_VALUE"
}

