#!/home/battleman/Programs/anaconda3/bin/python
# -*- coding: utf-8 -*-
import base64
import binascii
import re
import sys
# from pprint import pprint

from apiclient.discovery import build
from httplib2 import Http
from oauth2client import client, file, tools
POSITION = "/media/battleman/DATA/Documents/Programming/Python/Pymailextract/"
SCOPE = 'https://mail.google.com/'
POTENTIAL_FIELDS = ['from', 'to', 'cc', 'bcc', 'reply-to',
                    'sender', 'delivered-to', 'return-path', 'subject']
ALL_MAILS = set()
MAIL_REGEX = r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|" +\
    r"}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|" +\
    r"\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]" +\
    r"*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|" +\
    r"[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])" +\
    r"|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c" +\
    r"\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))"

PATTERN = re.compile(MAIL_REGEX, re.IGNORECASE)

DEBUG = False


def get_service():
    """
    Get a google api service, by reading and sending credentials. Automatic
    renewal if not valid.
    """
    store = file.Storage(POSITION+'credentials.json')
    creds = store.get()
    if not creds or creds.invalid:
        print("Credentials invalid, renewing")
        flow = client.flow_from_clientsecrets(
            POSITION+'client_secret.json', SCOPE)
        creds = tools.run_flow(flow, store)
    service = build('gmail', 'v1', http=creds.authorize(Http()))
    return service


def check_address(address):
    """
    Check whether an email address is valid

    Arguments:
        address: string containing what is believed to be an email address
    """
    try:
        if address and not (
                re.match(r".*\.(png|jpg|bmp|gif|)$", address, re.IGNORECASE) or
                re.match(r"^mail=", address, re.IGNORECASE) or
                re.match(r".*bounces.google.com$", address) or
                re.match(r".*smalalisting.*gmail.*", address) or
                re.match(r".*email.android.com$", address) or
                re.match(r"11d=", address) or
                r"mail.gmail.com" in address or
                re.match(r".*image.*\.(png|jpg)@.*", address)
        ):
            return True
        return False
    except TypeError:
        print(address)


def correct_address(address):
    """
    Corrects an email address (removes noisy characters, asks for confirmation
    if doubt)
    """
    if address[:2] == "**" or address[:2] == "b'":
        address = address[2:]

    if len(address) > 40:
        if DEBUG:
            return address
        try:
            print("The following address is odd:\n\t" + address)
            while True:
                confirm = input("Confirm you wish to keep it [Y/n]")
                if not confirm or confirm in "yYoO":
                    break
                if confirm in "nN":
                    address = None
                    break
                print("Please enter a valid answer")
        except EOFError:
            sys.exit("Exiting, as asked")
    return address


def parse_header(content):
    """
    Parses the header of a mail
    """
    for j in content['payload']['headers']:
        if j['name'].lower() in POTENTIAL_FIELDS:
            value = j['value']
            value = value.replace("\\r", " ").replace("\\n", " ")
            try:
                for match in re.findall(PATTERN, value):
                    if check_address(match[0]):
                        ALL_MAILS.add(match[0].lower())
            except AttributeError:
                pass


def decode_base64(data):
    """
    Decode base64, padding being optional.

    Arguments:
        data: Base64 data as an ASCII byte string

    Returns:
        The decoded byte string.
    """
    try:
        return base64.b64decode(str(data) + '=' * (-len(str(data)) % 4), '-_')
    except binascii.Error:
        try:
            return base64.b64decode(data, '-_')
        except binascii.Error:
            return None


def parse_body(mail):
    content = []
    pay = mail['payload']
    if 'parts' in pay:
        for part in pay['parts']:
            if (
                    ('body' in part) and
                    ('size' in part['body']) and
                    (part['body']['size'] > 0) and
                    ('data' in part['body'])
            ):
                content.append(part['body']['data'])

            if 'parts' in part:
                for subpart in part['parts']:
                    if (
                            ('body' in subpart) and
                            ('size' in subpart['body']) and
                            ('data' in subpart['body']) and
                            (subpart['body']['size'] > 0)
                    ):
                        content.append(subpart['body']['data'])
    if pay['body']['size'] > 0:
        content.append(pay['body']['data'])

    for cont in content:
        decoded = str(decode_base64(cont))
        decoded = decoded\
            .replace("\\r", " ")\
            .replace("\\n", " ")\
            .replace("\\t", " ")

        try:
            for match in list(re.findall(PATTERN, decoded)):
                if check_address(match[0]):
                    ALL_MAILS.add(match[0].lower())
        except AttributeError:
            pass


def get_message_list(token=None, query=""):
    service = get_service()
    if token:
        results = service.users().messages().list(userId='me',
                                                  q=query,
                                                  pageToken=token).execute()
    else:
        results = service\
            .users()\
            .messages()\
            .list(userId='me', q=query)\
            .execute()

    mails_list = results.get('messages', [])
    if mails_list:
        for mail in mails_list:
            uid = mail['id']
            content = service.users().messages().get(userId='me',
                                                     format="full",
                                                     id=uid).execute()
            parse_header(content)
            parse_body(content)
    try:
        return results['nextPageToken']
    except KeyError:
        return None


def main():
    """
    Main
    """
    i = 1
    print("Page 1")
    token = get_message_list()
    while token:
        i += 1
        print("Page", i)
        token = get_message_list(token=token)

    with open(POSITION+"email_addresses.txt", "w") as dst:
        for item in ALL_MAILS:
            addr = correct_address(item)
            if addr:
                dst.write("%s\n" % addr)


if __name__ == "__main__":
    main()
