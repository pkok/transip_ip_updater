"""
Makes sure that TransIP's DNS records are pointing to this device's IP.

This file heavily makes use of TransIP's API, v6.  For full documentation
of that API, please see:
    https://api.transip.nl/rest/docs.html
"""

import base64
import datetime
import json
import logging
import os
import random
from typing import TypedDict

import colorlog
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

API_ENDPOINT = "https://api.transip.nl/v6"

PRIVATE_KEY_FILE = os.environ.get("PRIVATE_KEY_FILE", "/config/private_key.pem")
LAST_UPDATED_IP_FILE = os.environ.get("PREVIOUS_IP_FILE", "/config/last_updated_ip.txt")
USERNAME = os.environ.get("USERNAME", "")
DOMAIN_TAGS = os.environ.get("DOMAIN_TAGS", [])
LOGGING_LEVEL = os.environ.get("LOGGING_LEVEL", "INFO")


class DnsEntry(TypedDict):
    """Model the TransIP DnsEntry type."""

    name: str
    expire: int
    type: str
    content: str


class Nameserver(TypedDict):
    """Models the TransIP Nameserver type."""

    hostname: str
    ipv4: str | None
    ipv6: str | None


class WhoisContact(TypedDict):
    """Models the TransIP WhoisContact type."""

    type: str
    firstName: str
    lastName: str
    companyName: str
    companyKvk: str
    companyType: str
    street: str
    number: str
    postalCode: str
    city: str
    phoneNumber: str
    faxNumber: str | None
    email: str
    country: str


class Domain(TypedDict):
    """Models the TransIP Domain type."""

    name: str
    nameservers: list[Nameserver]
    contacts: list[WhoisContact]
    authCode: str | None
    isTransferLocked: bool
    registrationDate: str
    renewalDate: str
    isWhitelabel: bool
    cancellationDate: str | None
    cancellationStatus: str | None
    isDnsOnly: bool
    tags: list[str]
    canEditDns: bool
    hasAutoDns: bool
    hasDnsSec: bool
    status: str


def validate_globals() -> None:
    """Check if system variables are set properly, and setup the logger."""
    global PRIVATE_KEY_FILE, USERNAME, DOMAIN_TAGS, LOGGING_LEVEL
    try:
        setup_logging(LOGGING_LEVEL)
    except ValueError:
        setup_logging(logging.INFO)
        logging.warn(
            f"Could not set logging level {LOGGING_LEVEL}; set to INFO instead"
        )
        LOGGING_LEVEL = logging.INFO

    if not os.path.isfile(os.path.abspath(PRIVATE_KEY_FILE)):
        logging.critical(f"Cannot find private key file; no file at {PRIVATE_KEY_FILE}")
        logging.critical("Terminating, bye 😢")
        exit(-1)

    if DOMAIN_TAGS is not None and not isinstance(DOMAIN_TAGS, list):
        DOMAIN_TAGS = [tag.strip() for tag in DOMAIN_TAGS.split(",")]
        count = len(DOMAIN_TAGS)
        domain_tags = ", ".join(DOMAIN_TAGS)
        logging.debug(f"Found {count} domain tags: {domain_tags}")
    elif not DOMAIN_TAGS:
        logging.debug("No domain tags provided")


def get_default_headers(token: str) -> dict:
    """Get HTTP headers with authentication info."""
    return {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}


def to_json(data: dict) -> str:
    """Transform a dict to a UTF-8 JSON object."""
    return json.dumps(data).encode('utf-8')


def setup_logging(logging_level: str | int) -> None:
    """Setup the logging facility properly."""
    log_colors = {
        'DEBUG': 'bold_blue',
        'INFO': 'bold_green',
        'WARNING': 'bold_yellow',
        'ERROR': 'bold_red',
        'CRITICAL': 'bold_red,bg_white',
    }

    formatter = colorlog.ColoredFormatter(
        "%(asctime)s %(log_color)s%(levelname)s%(reset)s %(message)s",
        log_colors=log_colors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.setLevel(logging_level)
    logger.addHandler(handler)
    logging.info(f"Set logging level to: {logger.level}")


def get_external_ip() -> str:
    """Let IPify tell you what your IP address for the world is."""
    external_ip = requests.get("https://api.ipify.org").text
    logging.info(f"External IP: {external_ip}")
    return external_ip.strip()


def authenticate(username, private_key_file) -> tuple[int, str]:
    """
    Get an authentication token from TransIP.

    You need to do something in the TransIP control panel first:
    - Go to https://www.transip.nl/cp/account/api/ and create a key pair.
    - Store the contents of the private key in PRIVATE_KEY_FILE.
    """
    data = {
        "login": username,
        "nonce": str(random.randint(0, int(1e11))),
        "read_only": False,
        "expiration_time": "5 minutes",
        "label": f"biebbot-{datetime.datetime.now()}",
        "global_key": True,
    }
    request_body = to_json(data)

    try:
        with open(private_key_file, "rb") as key_file:
            private_key = load_pem_private_key(key_file.read(), password=None)
    except Exception as e:
        logging.critical(f"Failed to read private key: {e}")
        raise e
    logging.debug(f"Private key read successfully: {private_key_file}")

    signature = private_key.sign(request_body, padding.PKCS1v15(), hashes.SHA512())
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    url = API_ENDPOINT + "/auth"
    headers = {"Signature": signature_b64}
    response = requests.post(url=url, headers=headers, data=request_body)
    logging.debug(f"Authentication status code: {response.status_code}")
    response_j = response.json()
    logging.debug(f"Authentication response.json(): {response_j}")
    return response.status_code, response.json()['token']


def get_domains(token: str, tags: list[str] | None = None) -> tuple[int, list[Domain]]:
    """Get a list of Domain names known to TransIP for the username."""
    headers = get_default_headers(token)

    url = API_ENDPOINT + "/domains"
    if tags is not None:
        tags = ",".join([s.strip() for s in tags])
        url += f"?tags={tags}"
    response = requests.get(url=url, headers=headers)
    return response.status_code, response.json()['domains']


def get_dns_entries(token: str, domain: Domain) -> tuple[int, list[DnsEntry]]:
    """Get a list of DnsEntry items for the provided Domain."""
    headers = get_default_headers(token)
    url = API_ENDPOINT + f"/domains/{domain['name']}/dns"
    response = requests.get(url=url, headers=headers)
    return response.status_code, response.json()['dnsEntries']


def set_dns_entry(token: str, domain: Domain, dns: DnsEntry) -> tuple[int, bool]:
    """
    Change a known DnsEntry of the Domain.

    The return value will inform you if it was successful.
    """
    headers = get_default_headers(token)
    url = API_ENDPOINT + f"/domains/{domain['name']}/dns"
    request_body = to_json({"dnsEntry": dns})
    response = requests.patch(url=url, headers=headers, data=request_body)
    success = response.status_code == 204
    return response.status_code, success


if __name__ == "__main__":
    validate_globals()
    logging.debug("Starting")
    external_ip = get_external_ip()
    if os.path.isfile(LAST_UPDATED_IP_FILE):
        with open(LAST_UPDATED_IP_FILE, "r") as f:
            old_external_ip = f.read().strip()
        if old_external_ip == external_ip:
            logging.info("My IP hasn't changed. Done.")
            exit(0)

    outdated_count = 0
    changed_count = 0
    _, token = authenticate(USERNAME, PRIVATE_KEY_FILE)
    _, domains = get_domains(token, tags=DOMAIN_TAGS)
    for domain in domains:
        _, dnses = get_dns_entries(token, domain)
        for dns in dnses:
            # Check if DNS entries need updating.
            # Only DNS A records should contain IP addresses, so we only look at those.
            if dns['type'] == "A" and external_ip != dns['content'].strip():
                outdated_count += 1
                logging.info(
                    f"{dns['name']}.{domain['name']} contained {dns['content']}"
                )
                dns['content'] = external_ip
                status, success = set_dns_entry(token, domain, dns)
                if success:
                    changed_count += 1
                    logging.info(f"Successfully changed content to {external_ip}")
                else:
                    logging.error(f"Could not change; HTTP status code {status}")
    logging.info(f"Changed {changed_count} of {outdated_count} outdated DNS records.")
    if changed_count == outdated_count:
        with open(LAST_UPDATED_IP_FILE, "w") as f:
            logging.debug(
                f"Trying to write {external_ip = } to {LAST_UPDATED_IP_FILE}."
            )
            f.write(external_ip)
            logging.debug("Success! Bye!")
