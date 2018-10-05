#!/home/battleman/Programs/anaconda3/bin/python
# -*- coding: utf-8 -*-
import base64
import binascii
import re
import sys
import threading
import time
from pprint import pprint
import os

from apiclient.discovery import build
from httplib2 import Http
from oauth2client import client, file, tools

POSITION = os.path.dirname(os.path.abspath(__file__))+"/"
SCOPE = 'https://mail.google.com/'
POTENTIAL_FIELDS = ['from', 'to', 'cc', 'bcc', 'reply-to',
                    'sender', 'delivered-to', 'return-path', 'subject']

ADDRESSES_LOCK = threading.Lock()
NUM_THREADS = 10
MAIL_REGEX = r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|" +\
    r"}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|" +\
    r"\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]" +\
    r"*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|" +\
    r"[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])" +\
    r"|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c" +\
    r"\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))"

PATTERN = re.compile(MAIL_REGEX, re.IGNORECASE)

DEBUG = True


def get_service():
    """
    Get a google api service, by reading and sending credentials. Automatic
    renewal if not valid.
    """
    store = file.Storage(POSITION+'token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('credentials.json', SCOPE)
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
            oddity = True
        try:
            print("The following address is odd:\n\t" + address)
            while True:
                confirm = input("Confirm you wish to keep it [Y/n]")
                if not confirm or confirm in "yYoO":
                    break
                if confirm in "nN":
                    oddity = True
                    break
                print("Please enter a valid answer")
        except EOFError:
            sys.exit("Exiting, as asked")
    return address, oddity


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


def parse_header(content):
    """
    Parses the header of a mail
    """
    addresses = set()
    for j in content['payload']['headers']:
        if j['name'].lower() in POTENTIAL_FIELDS:
            value = j['value']
            value = value.replace("\\r", " ").replace("\\n", " ")
            try:
                for match in re.findall(PATTERN, value):
                    if check_address(match[0]):
                        addresses.add(match[0].lower())
            except AttributeError:
                return None
    return addresses


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
    addresses = set()
    for cont in content:
        decoded = str(decode_base64(cont))
        decoded = decoded\
            .replace("\\r", " ")\
            .replace("\\n", " ")\
            .replace("\\t", " ")

        try:
            for match in list(re.findall(PATTERN, decoded)):
                if check_address(match[0]):
                    addresses.add(match[0].lower())
        except AttributeError:
            return None
    return addresses


def extract_emails(ids_list, service=None):
    found_addresses = set()
    if not ids_list:
        return
    if not service:
        service = get_service()

    for uid in ids_list:
        content = service.users().messages().get(userId='me',
                                                 format="full",
                                                 id=uid).execute()
        found_addresses = found_addresses.union(parse_header(content))
        found_addresses = found_addresses.union(parse_body(content))
    return found_addresses


def get_messages_list(token=None, query="", service=None):
    if not service:
        service = get_service()
    if token:
        results = service.users().messages().list(userId='me',
                                                  q=query,
                                                  pageToken=token).execute()
    else:
        results = service\
            .users().messages()\
            .list(userId='me', q=query)\
            .execute()

    mails_list = results.get('messages', [])
    try:
        return results['nextPageToken'], mails_list
    except KeyError:
        return None, mails_list


def chunks(target, num):
    """Yield successive n-sized chunks from l."""
    if num == 0:
        yield target
    else:
        for i in range(0, len(target), num):
            yield target[i:i + num]


def get_all_emails_id():
    """
    Returns all the IDs of the emails in the user's mailbox
    """
    service = get_service()
    mails_ids = []
    token, mails_list = get_messages_list(service=service)
    if not token:
        return [mail['id'] for mail in mails_list]
    while token:
        for mail in mails_list:
            mails_ids.append(mail['id'])
        token, mails_list = get_messages_list(token=token, service=service)
    return mails_ids

class MyThread(threading.Thread):
    def __init__(self, threadID, ids_list):
        super().__init__()
        self.threadID = threadID
        self.ids_list = ids_list
        self.result = set()

    def run(self):
        pprint("Thread {}, starting run".format(self.threadID))
        addresses = extract_emails(self.ids_list)
        # ADDRESSES_LOCK.acquire()
        pprint("Thread {}, giving back my results".format(self.threadID))
        self.result = self.result.union(addresses)
        # ADDRESSES_LOCK.release()

    def join(self):
        super().join()
        return self.result


def main():
    """
    Main
    """
    start = time.time()
    mails_ids = get_all_emails_id()
    if not mails_ids:
        return
    sublists = list(chunks(mails_ids, len(mails_ids)//NUM_THREADS))
    threads_list = []
    for num_thread in range(NUM_THREADS):
        thread = MyThread(num_thread, sublists[num_thread])
        thread.start()
        threads_list.append(thread)

    all_addresses = set()
    for thread in threads_list:
        all_addresses = all_addresses.union(thread.join())

    with open(POSITION+"parallelized_email_addresses.txt", "w") as dst:
        for item in all_addresses:
            addr = correct_address(item)
            if addr:
                dst.write("%s\n" % addr)
    print("Finished in ", time.time()-start, "seconds")


if __name__ == "__main__":
    main()
