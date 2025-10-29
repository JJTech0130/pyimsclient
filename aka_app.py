"""
Basic EAP-AKA challenge-response meant to be used with an Android app: https://github.com/JJTech0130/EAPAKAClient
Will talk to anything that responds to EAP-AKA challenges over HTTP.
"""
import requests
import logging

logger = logging.getLogger(__name__)

def eap_aka_for_device(device_ip: str):
    def eap_aka(challenge: str) -> str:
        logger.debug(f"Sending EAP-AKA request to app on device {device_ip} with challenge: {challenge}")
        # curl -X POST http://localhost:5080/eap_aka -d '{"challenge": "AQEARBcBAAABBQAAwuEBqb4tL1y/8fGaglBQHgIFAAAyxXCLn1IAACzWgocYKdo3CwUAAFBfNT2BJPL03anwrCC1+5I="}'
        url = f"http://{device_ip}:8080/eap_aka"
        payload = {"challenge": challenge}
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
        logger.info(f"EAP-AKA Response from app on device {device_ip}: {response.text}")
        return response.json().get("response", "")
    return eap_aka
