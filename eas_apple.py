"""
Implementation of the protocol iOS uses to talk to carrier entitlement (EAS) servers.
Used for Wi-Fi Calling, iCloudVoWiFi, and iMessage activation.
Reverse engineered by decompiling CommCenter on iOS 15.8.2.
You can get the EAS server URL using carrier_bundle.py to download and parse the carrier bundle for your carrier.
See main() for example usage, you must have an EAP-AKA challenge response function to use it.
"""
import base64
import gzip
import json
import requests
import uuid
from typing import Callable
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import logging

logger = logging.getLogger(__name__)

IMEI = "356303489086965"
USER_AGENT = "Entitlement/2.0 (iPhone) iOS/15.8.2 (19H384) Carrier Settings/50.0.2"
def create_session():
    # T-Mobile only accepts 4 non-default ciphers, so we have to manually add one
    # Apparently DEFAULT by itself might work, as that is somehow different from the actual default?
    class CustomCipherAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            context = create_urllib3_context(ciphers="DEFAULT:TLS_RSA_WITH_AES_256_GCM_SHA384")
            kwargs['ssl_context'] = context
            return super(CustomCipherAdapter, self).init_poolmanager(*args, **kwargs)

    # Create a session and mount the adapter
    session = requests.Session()

    # We'll also take this oppertunity to force all connections over a single, reused TCP socket
    # This makes authentication work properly (it should happen by default within a Session, though)
    session.mount("https://", CustomCipherAdapter(pool_maxsize=1, pool_block=True))
    return session

def make_requests(session: requests.Session, url: str, requests: list[dict]):
    logger.debug(f"Making requests to {url} with payload: {requests}")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-protocol-version": "2",
        "User-Agent": USER_AGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Encoding": "gzip"
    }

    request_body = gzip.compress(json.dumps(requests).encode('utf-8'))
    response = session.post(url, data=request_body, headers=headers)
    response.raise_for_status()

    logger.debug(f"Received response from {url}: {response.json()}")

    return response.json()

def authenticate(session: requests.Session, url: str, subscriber: str, challenge_cb: Callable):
    requests = [
        {
            "device-account-identifier": str(uuid.uuid4()).upper(), # Not sure if this UUID matters
            "auth-type": "EAP-AKA",
            "action-name": "getAuthentication",
            "subscriber-id": base64.b64encode(b'\x02\x00\x00;\x01' + subscriber.encode()).decode(),
            "request-id": 1,
            "unique-id": IMEI
        }
    ]

    responses = make_requests(session, url, requests)
    response = responses[0]
    assert response['status'] == 6302
    challenge = response['challenge']

    # Use the callback to process the challenge
    challenge_response = challenge_cb(challenge)

    requests = [{
            "payload": challenge_response,
            "action-name": "postChallenge",
            "request-id": 2
    }]

    responses = make_requests(session, url, requests)
    response = responses[0]
    assert response['status'] == 6000

    return response['token'] # Not sure what 'app-token' is for

def main():
    URL = "https://sentitlement2.mobile.att.net/"
    SUBSCRIBER = "0310280197204423@nai.epc.mnc280.mcc310.3gppnetwork.org"
    DEVICE_IP = "10.118.55.211"

    session = create_session()
    import aka_app
    authenticate(session, URL, SUBSCRIBER, aka_app.eap_aka_for_device(DEVICE_IP))

if __name__ == "__main__":
    from rich.logging import RichHandler
    logging.basicConfig(
        level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
    )
    main()
