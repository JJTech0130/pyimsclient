import base64
import gzip
import json
import requests
import uuid
import random
from typing import Callable
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import logging

logger = logging.getLogger(__name__)

IMEI = "350266804896192"
DEVICE_NAME = "Pixel 9"
USER_AGENT = f"Dalvik/2.1.0 (Linux; U; Android 13; {DEVICE_NAME} Build/TP1A.221005.002.B2)"
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
        "x-generic-protocol-version": "1.0",
        "x-generic-version": "1.0",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-protocol-version": "1",
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
    requests = [{
            "message-id": 1,
            "method": "3gppAuthentication",
            "device-id": base64.b64encode(IMEI.encode()).decode(),
            "device-type": 0,
            "os-type": 0,
            "device-name": DEVICE_NAME,
            "imsi-eap": subscriber
    }]

    responses = make_requests(session, url, requests)
    response = responses[0]
    assert response['response-code'] == 1003
    challenge = response['aka-challenge']

    # Use the callback to process the challenge
    challenge_response = challenge_cb(challenge)

    requests = [{
        "message-id": 1,
        "method": "3gppAuthentication",
        "device-id": base64.b64encode(IMEI.encode()).decode(),
        "device-type": 0,
        "os-type": 0,
        "device-name": DEVICE_NAME,
        "imsi-eap": subscriber,
        "aka-challenge-rsp": challenge_response
    }]

    responses = make_requests(session, url, requests)
    response = responses[0]
    assert response['response-code'] == 1000

    # Using the token is optional, you can just keep the session open
    return response['aka-token']

def main():
    URL = "https://sentitlement2.mobile.att.net/WFC"
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
