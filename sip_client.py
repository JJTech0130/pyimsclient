from datetime import datetime
import socket
import sys
import time
import re
import base64
import random

# ---- Configuration ----
LOCAL_IPV6 = "2600:380:a5c3:8a9a:0:68:a3b2:ec01"   # change if you need to use a different local IPv6
PCSCF_IPV6 = "2001:1890:1f8:20cd::1:2"
IMSI = "310280197204423"
IMEI = "356303489086965"
REALM = "one.att.net"
USERNAME = IMSI + "@private.att.net"
#LOCAL_PORT = 5060    # local UDP port we bind to
SOCKET_TIMEOUT = 5.0 # seconds to wait for responses

# ---- EAP-AKA stub ----
def eap_aka_respond(challenge_b64: str) -> str:
    """
    Stub function that receives a base64 challenge string and returns a base64 response string.

    Replace this with real EAP-AKA logic or integration with your SIM/AKA library.

    For demo purposes this returns a deterministic pseudo-response:
      base64("RESP:" + challenge_b64[::-1] + ":"random)
    """
    # Validate input (just to be tidy)
    try:
        _ = base64.b64decode(challenge_b64)
    except Exception:
        # If input isn't valid base64, still produce a base64 response but mark it
        challenge_b64 = base64.b64encode(challenge_b64.encode()).decode()

    # Build a fake response (you'll replace this)
    rnd = ("%04x" % random.randrange(0, 0x10000))
    response_raw = "RESP:".encode() + challenge_b64.encode() + b":" + rnd.encode()
    response_b64 = base64.b64encode(response_raw).decode()
    return response_b64

def bind_socket_to_iface(sock: socket.socket, ifname: str):
    if sys.platform == "darwin":
        ifindex = socket.if_nametoindex(ifname)
        level = socket.IPPROTO_IPV6 if sock.family == socket.AF_INET6 else socket.IPPROTO_IP
        optname = 125 if sock.family == socket.AF_INET6 else 25 # IPV6_BOUND_IF / IP_BOUND_IF
        sock.setsockopt(level, optname, ifindex)
    elif sys.platform.startswith("linux"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())

def create_sip_register_request():
    # Generate unique identifiers
    call_id = "Mnnd3KecVIXNL1CIUQyjo9xJ"
    session_id = "23bb5f09d0ef6afaa82ce50739e249cb"
    branch = "z9hG4bKzoVCx1ACamdbS4e"
    tag = "QF49yEDlsZ"
    
    # Current timestamp in the required format
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    #sa_list = "alg=hmac-md5-96;ealg=aes-cbc;mod=trans;port-c=61659;port-s=55188;prot=esp;spi-c=194022009;spi-s=137604464,ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c=61659;port-s=55188;prot=esp;spi-c=194022009;spi-s=137604464,ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=trans;port-c=61659;port-s=55188;prot=esp;spi-c=194022009;spi-s=137604464,ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=61659;port-s=55188;prot=esp;spi-c=194022009;spi-s=137604464"
    sa_list = [
        {
            "alg": "hmac-md5-96",
            "ealg": "aes-cbc",
            "mod": "trans",
            "port-c": 61659,
            "port-s": 55188,
            "prot": "esp",
            "spi-c": 194022009,
            "spi-s": 137604464
        },
        {
            "alg": "hmac-md5-96",
            "ealg": "null",
            "mod": "trans",
            "port-c": 61659,
            "port-s": 55188,
            "prot": "esp",
            "spi-c": 194022009,
            "spi-s": 137604464
        },
        {
            "alg": "hmac-sha-1-96",
            "ealg": "aes-cbc",
            "mod": "trans",
            "port-c": 61659,
            "port-s": 55188,
            "prot": "esp",
            "spi-c": 194022009,
            "spi-s": 137604464
        },
        {
            "alg": "hmac-sha-1-96",
            "ealg": "null",
            "mod": "trans",
            "port-c": 61659,
            "port-s": 55188,
            "prot": "esp",
            "spi-c": 194022009,
            "spi-s": 137604464
        }
    ]
    # encode the sa_list into Security-Client
    sa_list_str = ",".join([";".join(["ipsec-3gpp"] + [f"{k}={v}" for k, v in sa.items()]) for sa in sa_list])

    # SIP headers
    headers = [
        f"REGISTER sip:{REALM} SIP/2.0",
        f"To: <sip:{IMSI}@{REALM}>",
        f"From: <sip:{IMSI}@{REALM}>;tag={tag}",
        f"Expires: 600000",
        #f"Require: sec-agree",
        #f"Proxy-Require: sec-agree",
        #f"Security-Client: {sa_list_str}",
        f"Call-ID: {call_id}",
        f"Session-ID: {session_id}",
        f"Geolocation: <cid:{IMSI}@{REALM}>",
        f"Geolocation-Routing: yes",
        f"Contact: <sip:[{LOCAL_IPV6}]:5060>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip;+sip.instance=\"<urn:gsma:imei:{IMEI}>\";text",
        f'Authorization: Digest nonce="",uri="sip:{REALM}",realm="{REALM}",username="{USERNAME}",response=""',
        f"CSeq: 1 REGISTER",
        f"Via: SIP/2.0/UDP [{LOCAL_IPV6}]:5060;branch={branch};rport",
        f"Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE",
        f"Max-Forwards: 70",
        f"Supported: 100rel,path,replaces",
        f"User-Agent: iOS/16.1.2 iPhone",
        f"Content-Type: application/pidf+xml"
    ]
    
    # PIDF XML content
    pidf_content = f'''<?xml version="1.0"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10" xmlns:gml="http://www.opengis.net/gml" xmlns:gs="http://www.opengis.net/pidflo/1.0" xmlns:cl="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr" entity="sip:{IMSI}@{REALM}">
<tuple id="Wifi">
<status>
<gp:geopriv>
<gp:location-info>
<cl:civicAddress>
<cl:country>US</cl:country>
</cl:civicAddress>
</gp:location-info>
<gp:usage-rules/>
</gp:geopriv>
</status>
<dm:timestamp>{timestamp}</dm:timestamp>
</tuple>
</presence>'''
    
    # Calculate content length
    content_length = len(pidf_content)
    headers.append(f"Content-Length: {content_length}")
    
    # Build the complete SIP message
    sip_message = "\r\n".join(headers) + "\r\n\r\n" + pidf_content
    
    return sip_message

# ---- Main flow ----
def main():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    #sock.bind((LOCAL_IPV6, 5060))
    bind_socket_to_iface(sock, "utun8")
    sock.settimeout(SOCKET_TIMEOUT)

    register_request = create_sip_register_request()
    print(">>> Sending REGISTER:\n" + register_request)
    sock.connect((PCSCF_IPV6, 5060))
    sock.send(register_request.encode())
    try:
        data = sock.recv(8192)
        print("<<< Received response:\n" + data.decode())
    except socket.timeout:
        print("No response to REGISTER (timeout).")
    sock.close()
    

    # pcscf_ip = sys.argv[1]
    # pcscf_port = int(sys.argv[2])
    # imsi = sys.argv[3]
    # mcc, mnc = imsi[:3], imsi[3:6]
    # user = "0" + imsi + "@ims.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"

    # local_ip = "2600:380:88f7:3af6:0:41:5e93:601"
    # local_port = LOCAL_PORT

    # addr = (pcscf_ip, pcscf_port, 0, 0)  # tuple form for IPv6 sendto

    # sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    # sock.bind(("::", local_port))
    # bind_socket_to_iface(sock, "utun8") 
    # sock.settimeout(SOCKET_TIMEOUT)
    # try:
    #     pass
    # except Exception as e:
    #     print(f"Failed to bind local {(local_ip, local_port)}: {e}")
    #     print("Try running with appropriate privileges or change LOCAL_IPV6/LOCAL_PORT in the script.")
    #     sys.exit(1)

    # call_id = f"{int(time.time())}-{random.randrange(0,10000)}@{local_ip}"
    # cseq = 1
    # branch = "z9hG4bK-" + ("%08x" % random.randrange(0, 0xFFFFFFFF))

    # # 1) Send initial REGISTER (no auth)
    # reg = build_register(pcscf_ip, pcscf_port, user, local_ip, local_port, call_id, cseq, branch)
    # print(">>> Sending initial REGISTER (no auth):\n" + reg)
    # #sock.connect(addr)
    # sock.sendto(reg.encode(), addr)
    # #sock.send(reg.encode())

    # # 2) Receive response
    # try:
    #     data, remote = sock.recvfrom(8192)
    # except socket.timeout:
    #     print("No response to initial REGISTER (timeout).")
    #     sock.close()
    #     return

    # resp = parse_sip_response(data)
    # print("<<< Received response:\n" + resp.get("raw", ""))

    # status = resp.get("status_code")
    # headers = resp.get("headers", {})

    # if status == 401 or status == 407:
    #     print(f"Authentication required (status {status}). Looking for EAP-AKA challenge...")

    #     challenge_b64 = extract_eap_challenge_from_headers(headers)
    #     if not challenge_b64:
    #         print("No EAP-AKA challenge found in headers. Authentication headers present:")
    #         for k, vs in headers.items():
    #             if k.startswith("www-auth") or k.startswith("proxy-auth"):
    #                 for v in vs:
    #                     print(f"  {k}: {v}")
    #         print("Exiting. Replace stub parsing or provide an actual challenge header format.")
    #         sock.close()
    #         return

    #     print(f"Found EAP challenge (base64): {challenge_b64}")

    #     # 3) Call the stub EAP-AKA responder
    #     response_b64 = eap_aka_respond(challenge_b64)
    #     print(f"Computed EAP-AKA response (base64): {response_b64}")

    #     # 4) Construct Authorization header and re-send REGISTER
    #     # We choose a simple Authorization header form: Authorization: EAP-AKA response="<base64>"
    #     # Real servers may expect a different header format (e.g., Digest with eap=..., or specific params)
    #     auth_header = f'Authorization: EAP-AKA response="{response_b64}"'

    #     cseq += 1
    #     branch = "z9hG4bK-" + ("%08x" % random.randrange(0, 0xFFFFFFFF))
    #     reg2 = build_register(pcscf_ip, pcscf_port, user, local_ip, local_port, call_id, cseq, branch, auth_header=auth_header)
    #     print(">>> Sending REGISTER with EAP-AKA Authorization:\n" + reg2)
    #     sock.sendto(reg2.encode(), addr)

    #     # 5) Wait for final response
    #     try:
    #         data2, remote2 = sock.recvfrom(8192)
    #     except socket.timeout:
    #         print("No response to REGISTER-with-auth (timeout).")
    #         sock.close()
    #         return

    #     resp2 = parse_sip_response(data2)
    #     print("<<< Received response:\n" + resp2.get("raw", ""))
    #     final_status = resp2.get("status_code")
    #     if final_status and 200 <= final_status < 300:
    #         print("Registration succeeded (2xx).")
    #     else:
    #         print(f"Registration did not succeed. Status {final_status} - check server logs and real EAP-AKA exchange.")
    # else:
    #     print(f"Server responded with status {status}. No authentication required or different flow.")
    # sock.close()

if __name__ == "__main__":
    main()
