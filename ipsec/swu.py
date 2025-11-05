import serial
import struct
import socket
import random
import time
import select
import sys
import os
import fcntl
import subprocess

# import multiprocessing
import multiprocess as multiprocessing
import requests

from optparse import OptionParser
from binascii import hexlify, unhexlify

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import ipsec.eap
from ._const import *


# requests.packages.urllib3.disable_warnings()

"""

Ike Process

IPsec_encoder (receives data from tunnel interface -> encrypts and sends it towards the server/epdg)

IPsec_decoder (receives encrypted data from server/epdg -> decypts it and sends it to the tunnel interface)

"""


class swu:

    def __init__(self, source_address, epdg_address, apn, modem, default_gateway, mcc, mnc, imsi, ki, op, opc, netns, sqn):
        self.source_address = source_address
        self.epdg_address = epdg_address
        self.apn = apn
        self.com_port = modem
        self.default_gateway = default_gateway
        self.mcc = mcc
        self.mnc = mnc
        self.imsi = imsi

        self.ki = ki
        self.op = op
        self.opc = opc

        self.netns_name = netns
        self.sqn = sqn

        self.set_variables()
        self.set_udp()  # default
        self.create_socket(self.client_address)
        self.create_socket_nat(self.client_address_nat)
        self.create_socket_esp(self.client_address_esp)
        self.userplane_mode = ESP_PROTOCOL

        self.sk_ENCR_NULL_pad_length = 0  # [0 or 1 byte] SK payload is not definied in RFC for IKEv2. Some vendors don't use pad length byte, others use.

    def set_variables(self):
        self.port = DEFAULT_IKE_PORT
        self.port_nat = DEFAULT_IKE_NAT_TRAVERSAL_PORT
        self.client_address = (self.source_address, self.port)
        self.client_address_nat = (self.source_address, self.port_nat)
        self.client_address_esp = (self.source_address, 0)
        self.timeout = DEFAULT_TIMEOUT_UDP
        self.state = 0
        self.server_address = (self.epdg_address, self.port)
        self.server_address_nat = (self.epdg_address, self.port_nat)
        self.server_address_esp = (self.epdg_address, 0)
        self.message_id_request = 0
        self.message_id_responses = 0

        self.role = ROLE_INITIATOR
        self.old_ike_message_received = False
        self.ike_spi_initiator_old = None
        self.ike_spi_responder_old = None
        self.next_reauth_id = None

        self.check_nat = True

        self.set_identification(IDI, ID_RFC822_ADDR, "0" + self.imsi + "@nai.epc.mnc" + self.mnc + ".mcc" + self.mcc + ".3gppnetwork.org")
        #       self.set_identification(IDR,ID_FQDN, self.apn + '.apn.epc.mnc' + self.mnc + '.mcc' + self.mcc + '.3gppnetwork.org')
        self.set_identification(IDR, ID_FQDN, self.apn)

        self.ike_decoded_header = {}
        self.decodable_payloads = [SA, KE, IDI, IDR, CERT, CERTREQ, AUTH, NINR, N, D, V, TSI, TSR, SK, CP, EAP]

        self.iana_diffie_hellman = {MODP_768_bit: 768, MODP_1024_bit: 1024, MODP_1536_bit: 1536, MODP_2048_bit: 2048, MODP_3072_bit: 3072, MODP_4096_bit: 4096, MODP_6144_bit: 6144, MODP_8192_bit: 8192}
        self.prf_function = {
            PRF_HMAC_MD5: hashes.MD5(),
            PRF_HMAC_SHA1: hashes.SHA1(),
            # PRF_HMAC_TIGER :        3
            # PRF_AES128_XCBC :       4
            PRF_HMAC_SHA2_256: hashes.SHA256(),
            PRF_HMAC_SHA2_384: hashes.SHA384(),
            PRF_HMAC_SHA2_512: hashes.SHA512(),
            # PRF_AES128_CMAC :       8
        }
        self.prf_key_len_bytes = {
            PRF_HMAC_MD5: 16,
            PRF_HMAC_SHA1: 20,
            # PRF_HMAC_TIGER :        -,
            PRF_AES128_XCBC: 16,
            PRF_HMAC_SHA2_256: 32,
            PRF_HMAC_SHA2_384: 48,
            PRF_HMAC_SHA2_512: 64,
            PRF_AES128_CMAC: 16,
        }
        self.integ_function = {
            NONE: None,
            AUTH_HMAC_MD5_96: hashes.MD5(),
            AUTH_HMAC_SHA1_96: hashes.SHA1(),
            # AUTH_DES_MAC :	            -,
            # AUTH_KPDK_MD5 :             -,
            # AUTH_AES_XCBC_96 :          16,
            # AUTH_HMAC_MD5_128 :         -,
            # AUTH_HMAC_SHA1_160 :        -,
            # AUTH_AES_CMAC_96 :          -,
            # AUTH_AES_128_GMAC :         16,
            # AUTH_AES_192_GMAC :        24,
            # AUTH_AES_256_GMAC :        32,
            AUTH_HMAC_SHA2_256_128: hashes.SHA256(),
            AUTH_HMAC_SHA2_384_192: hashes.SHA384(),
            AUTH_HMAC_SHA2_512_256: hashes.SHA512(),
        }
        self.integ_key_len_bytes = {
            NONE: 0,
            AUTH_HMAC_MD5_96: 16,
            AUTH_HMAC_SHA1_96: 20,
            # AUTH_DES_MAC :	            -,
            # AUTH_KPDK_MD5 :             -,
            # AUTH_AES_XCBC_96 :          16,
            # AUTH_HMAC_MD5_128 :         -,
            # AUTH_HMAC_SHA1_160 :        -,
            # AUTH_AES_CMAC_96 :          -,
            # AUTH_AES_128_GMAC :         16,
            # AUTH_AES_192_GMAC :        24,
            # AUTH_AES_256_GMAC :        32,
            AUTH_HMAC_SHA2_256_128: 32,
            AUTH_HMAC_SHA2_384_192: 48,
            AUTH_HMAC_SHA2_512_256: 64,
        }
        self.integ_key_truncated_len_bytes = {
            NONE: 0,
            AUTH_HMAC_MD5_96: 12,
            AUTH_HMAC_SHA1_96: 12,
            # AUTH_DES_MAC :	            -,
            # AUTH_KPDK_MD5 :             -,
            # AUTH_AES_XCBC_96 :          12,
            # AUTH_HMAC_MD5_128 :         -,
            # AUTH_HMAC_SHA1_160 :        -,
            # AUTH_AES_CMAC_96 :          -,
            # AUTH_AES_128_GMAC :         16?,
            # AUTH_AES_192_GMAC :        24?,
            # AUTH_AES_256_GMAC :        32?,
            AUTH_HMAC_SHA2_256_128: 16,
            AUTH_HMAC_SHA2_384_192: 24,
            AUTH_HMAC_SHA2_512_256: 32,
        }
        self.configuration_payload_len_bytes = {
            INTERNAL_IP4_ADDRESS: 4,
            INTERNAL_IP4_NETMASK: 4,
            INTERNAL_IP4_DNS: 4,
            INTERNAL_IP4_NBNS: 4,
            INTERNAL_IP4_DHCP: 4,
            APPLICATION_VERSION: None,
            INTERNAL_IP6_ADDRESS: 16,
            INTERNAL_IP6_DNS: 16,
            INTERNAL_IP6_DHCP: 16,
            INTERNAL_IP4_SUBNET: 8,
            SUPPORTED_ATTRIBUTES: None,
            INTERNAL_IP6_SUBNET: 17,
            MIP6_HOME_PREFIX: 21,
            INTERNAL_IP6_LINK: None,
            INTERNAL_IP6_PREFIX: 17,
            HOME_AGENT_ADDRESS: None,  # 16 or 20
            P_CSCF_IP4_ADDRESS: 4,
            P_CSCF_IP6_ADDRESS: 16,
            FTT_KAT: 2,
            EXTERNAL_SOURCE_IP4_NAT_INFO: 6,
            TIMEOUT_PERIOD_FOR_LIVENESS_CHECK: 4,
            INTERNAL_DNS_DOMAIN: None,
            INTERNAL_DNSSEC_TA: None,
        }
        self.errors = {OK: "OK", TIMEOUT: "TIMEOUT", REPEAT_STATE: "REPEAT_STATE", DECODING_ERROR: "DECODING_ERROR", MANDATORY_INFORMATION_MISSING: "MANDATORY_INFORMATION_MISSING", OTHER_ERROR: "OTHER_ERROR"}

    def return_integrity_algorithm_name(self):
        integ_alg = {AUTH_HMAC_MD5_96: "HMAC_MD5_96 [RFC2403]", AUTH_HMAC_SHA1_96: "HMAC_SHA1_96 [RFC2404]", AUTH_HMAC_SHA2_256_128: "HMAC_SHA2_256_128 [RFC4868]", AUTH_HMAC_SHA2_384_192: "HMAC_SHA2_384_192 [RFC4868]", AUTH_HMAC_SHA2_512_256: "HMAC_SHA2_512_256 [RFC4868]", NONE: "NONE [RFC4306]"}
        return integ_alg.get(self.negotiated_integrity_algorithm, "UNKNOWN")

    def return_encryption_algorithm_name(self):
        encr_alg = ""
        key_size = self.negotiated_encryption_algorithm_key_size
        if key_size == 128 and self.negotiated_encryption_algorithm == ENCR_AES_CBC:
            encr_alg = "AES-CBC-128 [RFC3602]"
        elif key_size == 256 and self.negotiated_encryption_algorithm == ENCR_AES_CBC:
            encr_alg = "AES-CBC-256 [RFC3602]"
        elif self.negotiated_encryption_algorithm == ENCR_NULL:
            encr_alg = "NULL [RFC2410]"
        return encr_alg

    def return_integrity_algorithm_child_name(self):
        integ_alg = {AUTH_HMAC_MD5_96: "HMAC-MD5-96 [RFC2403]", AUTH_HMAC_SHA1_96: "HMAC-SHA-1-96 [RFC2404]", AUTH_HMAC_SHA2_256_128: "HMAC-SHA-256-128 [RFC4868]", AUTH_HMAC_SHA2_384_192: "HMAC-SHA-384-192 [RFC4868]", AUTH_HMAC_SHA2_512_256: "HMAC-SHA-512-256 [RFC4868]", NONE: "NULL"}
        return integ_alg.get(self.negotiated_integrity_algorithm_child, "UNKNOWN")

    def return_encryption_algorithm_child_name(self):
        encr_alg = ""
        if self.negotiated_encryption_algorithm_child == ENCR_AES_CBC:
            encr_alg = "AES-CBC [RFC3602]"
        elif self.negotiated_encryption_algorithm_child == ENCR_AES_GCM_8:
            encr_alg = "AES-GCM [RFC4106]"
        elif self.negotiated_encryption_algorithm_child == ENCR_AES_GCM_12:
            encr_alg = "AES-GCM [RFC4106]"
        elif self.negotiated_encryption_algorithm_child == ENCR_AES_GCM_16:
            encr_alg = "AES-GCM [RFC4106]"
        elif self.negotiated_encryption_algorithm_child == ENCR_NULL:
            encr_alg = "NULL"
        return encr_alg

    def print_ikev2_decryption_table(self):
        print("IKEv2 DECRYPTION TABLE INFO (Wireshark):")
        text = toHex(self.ike_spi_initiator) + "," + toHex(self.ike_spi_responder) + ","
        text += toHex(self.SK_EI) + "," + toHex(self.SK_ER) + ',"' + self.return_encryption_algorithm_name() + '",'
        text += toHex(self.SK_AI) + "," + toHex(self.SK_AR) + ',"' + self.return_integrity_algorithm_name() + '"'
        print(text)
        text = toHex(self.ike_spi_responder) + "," + toHex(self.ike_spi_initiator) + ","
        text += toHex(self.SK_ER) + "," + toHex(self.SK_EI) + ',"' + self.return_encryption_algorithm_name() + '",'
        text += toHex(self.SK_AR) + "," + toHex(self.SK_AI) + ',"' + self.return_integrity_algorithm_name() + '"'
        print(text)

    def print_esp_sa(self):
        print("ESP SA INFO (wireshark):")
        text = '"IPv4","' + self.source_address + '","' + self.epdg_address + '","0x' + toHex(self.spi_resp_child)
        text += '","' + self.return_encryption_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_EI)
        text += '","' + self.return_integrity_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_AI) + '"'
        print(text)
        text = '"IPv4","' + self.epdg_address + '","' + self.source_address + '","0x' + toHex(self.spi_init_child)
        text += '","' + self.return_encryption_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_ER)
        text += '","' + self.return_integrity_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_AR) + '"'
        print(text)

    def set_timeout(self, value):
        self.timeout = value

    def set_udp(self):
        self.socket_type = UDP

    def create_socket(self, client_address):

        if self.socket_type == UDP:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            exit()

        self.socket.bind(client_address)
        self.socket.settimeout(self.timeout)

    def create_socket_nat(self, client_address):

        if self.socket_type == UDP:
            self.socket_nat = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            exit()

        self.socket_nat.bind(client_address)
        self.socket_nat.settimeout(self.timeout)

    def create_socket_esp(self, client_address):
        # Stub using pipe
        r, w = os.pipe()
        self.socket_esp = w
        # self.socket_esp = socket.socket(socket.AF_INET, socket.SOCK_RAW, ESP_PROTOCOL)
        # self.socket_esp.bind(client_address)

    def set_server(self, address):
        self.server_address = (address, self.port)

    def set_server_nat(self, address):
        self.server_address_nat = (address, self.port_nat)

    def set_server_esp(self, address):
        self.server_address_esp = (address, 0)

    def send_data(self, data):
        if self.userplane_mode == ESP_PROTOCOL:
            self.socket.sendto(data, self.server_address)
        else:
            self.socket_nat.sendto(b"\x00" * 4 + data, self.server_address_nat)

    def return_random_bytes(self, size):
        if size == 0:
            return b""
        if size == 4:
            return struct.pack("!I", random.randrange(pow(2, 32) - 1))
        if size == 8:
            return struct.pack("!Q", random.randrange(pow(2, 64) - 1))
        if size == 16:
            return struct.pack("!Q", random.randrange(pow(2, 64) - 1)) + struct.pack("!Q", random.randrange(pow(2, 64) - 1))

    def return_random_int(self, size):
        if size == 4:
            return random.randrange(pow(2, 32) - 1)
        if size == 8:
            return random.randrange(pow(2, 64) - 1)
        if size == 16:
            return random.randrange(pow(2, 128) - 1)

    def return_flags(self, value):  # works with value or tuple

        if type(value) is int:
            rvi = (value // 8) % 8
            return (rvi // 4, (rvi // 2) % 2, rvi % 2)
        else:  # is a tuple with (r,v,i)
            return 32 * value[0] + 16 * value[1] + 8 * value[2]

    def dh_create_private_key_and_public_bytes(self, key_size):
        prime = {
            768: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF,
            1024: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF,
            1536: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
            2048: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
            3072: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
            4096: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
            6144: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
            8192: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF,
        }
        g = 2
        self.pn = dh.DHParameterNumbers(prime[key_size], g)
        parameters = self.pn.parameters()
        self.dh_private_key = parameters.generate_private_key()
        self.dh_public_key_bytes = self.dh_private_key.public_key().public_numbers().y.to_bytes(key_size // 8, "big")

    def dh_calculate_shared_key(self, peer_public_key_bytes):
        peer_public_numbers = dh.DHPublicNumbers(int.from_bytes(peer_public_key_bytes, byteorder="big"), self.pn)
        peer_public_key = peer_public_numbers.public_key()
        self.dh_shared_key = self.dh_private_key.exchange(peer_public_key)

        print("DIFFIE-HELLMAN KEY", toHex(self.dh_shared_key))

    def get_identity(self):
        imsi = https_imsi(self.com_port)
        self.imsi = imsi
        self.set_identification(IDI, ID_RFC822_ADDR, "0" + self.imsi + "@nai.epc.mnc" + self.mnc + ".mcc" + self.mcc + ".3gppnetwork.org")

    #######################################################################################################################
    #######################################################################################################################
    ################                            D E C O D E     F U N C T I O N S                          ################
    #######################################################################################################################
    #######################################################################################################################

    def decode_header(self, data):
        try:
            # if True:
            self.ike_decoded_header["initiator_spi"] = data[0:8]
            self.ike_decoded_header["responder_spi"] = data[8:16]
            self.ike_decoded_header["next_payload"] = data[16]
            self.ike_decoded_header["major_version"] = data[17] // 16
            self.ike_decoded_header["minor_version"] = data[17] % 16
            self.ike_decoded_header["exchange_type"] = data[18]
            self.ike_decoded_header["flags"] = self.return_flags(data[19])
            self.ike_decoded_header["message_id"] = struct.unpack("!I", data[20:24])[0]
            self.ike_decoded_header["length"] = struct.unpack("!I", data[24:28])[0]  # header + payloads

            if self.ike_spi_responder == (0).to_bytes(8, "big") and self.ike_spi_initiator == self.ike_decoded_header["initiator_spi"]:
                self.ike_spi_responder = self.ike_decoded_header["responder_spi"]
                self.ike_decoded_header_ok = True
                self.old_ike_message_received = False
                return

            if self.ike_spi_initiator == self.ike_decoded_header["initiator_spi"] and self.ike_spi_responder == self.ike_decoded_header["responder_spi"]:
                self.ike_decoded_header_ok = True
                self.old_ike_message_received = False
                return

            if self.ike_spi_initiator_old == self.ike_decoded_header["initiator_spi"] and self.ike_spi_responder_old == self.ike_decoded_header["responder_spi"]:
                self.ike_decoded_header_ok = True
                self.old_ike_message_received = True
                return

            self.ike_decoded_header_ok = False
            return
        except:
            self.ike_decoded_header_ok = False

    def decode_generic_payload_header(self, data, position, payload_type):
        ike_decoded_payload_header = {}
        ike_decoded_payload_header["next_payload"] = data[position]
        ike_decoded_payload_header["C"] = data[position + 1] // 128
        ike_decoded_payload_header["length"] = struct.unpack("!H", data[position + 2 : position + 4])[0]
        ike_decoded_payload_header["data"] = data[position + 4 : position + ike_decoded_payload_header["length"]]

        # to be used for SK decryption
        self.current_next_payload = ike_decoded_payload_header["next_payload"]

        if payload_type in self.decodable_payloads:
            ike_decoded_payload_header["decoded"] = [payload_type, self.decode_payload_type(payload_type, ike_decoded_payload_header["data"])]
        else:
            ike_decoded_payload_header["decoded"] = [payload_type, None]

        position += ike_decoded_payload_header["length"]
        return position, ike_decoded_payload_header["decoded"], ike_decoded_payload_header["next_payload"]

    def decode_payload(self, data, next_payload, position=28):  # by default it uses position 28 for normal

        decoded_payload = []
        while position < len(data):

            position, payload_decoded, next_payload = self.decode_generic_payload_header(data, position, next_payload)
            decoded_payload.append(payload_decoded)

        return (True, decoded_payload)

    def decode_ike(self, data):
        self.current_packet_received = data

        try:
            # if True:
            self.decode_header(data)
            if self.ike_decoded_header_ok == False:
                self.ike_decoded_ok = False
            else:

                (self.decoded_payload_ok, self.decoded_payload) = self.decode_payload(data, self.ike_decoded_header["next_payload"])
                if self.decoded_payload_ok == False:
                    self.ike_decoded_ok = False
                else:
                    self.ike_decoded_ok = True
                    print("received decoded message:")
                    print(self.decoded_payload)
        except:
            self.ike_decoded_ok = False

    def decode_payload_type(self, type, data):
        payload_type = {
            SA: self.decode_payload_type_sa,
            KE: self.decode_payload_type_ke,
            IDI: self.decode_payload_type_idi,
            IDR: self.decode_payload_type_idr,
            CERT: self.decode_payload_type_cert,
            CERTREQ: self.decode_payload_type_certreq,
            AUTH: self.decode_payload_type_auth,
            NINR: self.decode_payload_type_ninr,
            N: self.decode_payload_type_n,
            D: self.decode_payload_type_d,
            V: self.decode_payload_type_v,
            TSI: self.decode_payload_type_tsi_tsr,
            TSR: self.decode_payload_type_tsi_tsr,
            SK: self.decode_payload_type_sk,
            CP: self.decode_payload_type_cp,
            EAP: self.decode_payload_type_eap,
        }
        func = payload_type.get(type, self.unsupported_payload_type)
        return func(data)

    def decode_payload_type_sa(self, data):
        spi = b""
        if data[5] != 0:
            spi = data[8 : 8 + data[6]]
        return [data[4], data[5], spi]  # proposal number, protocol_id, spi

    def decode_payload_type_ke(self, data):
        return [struct.unpack("!H", data[0:2])[0], data[4:]]  # diffie-hellman group, key

    def decode_payload_type_idi(self, data):
        return [data[0], data[4:]]

    def decode_payload_type_idr(self, data):
        return [data[0], data[4:]]

    def decode_payload_type_cert(self, data):
        return [data[0], data[1:]]

    def decode_payload_type_certreq(self, data):
        return [data[0], data[1:]]

    def decode_payload_type_auth(self, data):
        return [data[0], data[4:]]

    def decode_payload_type_ninr(self, data):
        return [data]  # nounce_received

    def decode_payload_type_n(self, data):
        spi = b""
        notification_data = b""
        if data[1] != 0:  # spi present
            spi = data[4 : 4 + data[1]]
        if len(data) > 4 + data[1]:  # notification data present
            notification_data = data[4 + data[1] :]
        return [data[0], struct.unpack("!H", data[2:4])[0], spi, notification_data]  # protocol_id, notify_message_type, spi, notification_data

    def decode_payload_type_d(self, data):
        spi = b""
        spi_list = []
        num_of_spi = 0
        if data[1] != 0:  # spi present
            num_of_spi = struct.unpack("!H", data[2:4])[0]
            for i in range(num_of_spi):
                spi_list.append(data[4 + i * data[1] : 4 + (i + 1) * data[1]])

        return [data[0], num_of_spi, spi_list]  # [protocol_id, number of spi, [spi1, spi2, ... spi n]]

    def decode_payload_type_v(self, data):
        return [data]

    def decode_payload_type_tsi_tsr(self, data):
        num_of_ts = data[0]
        ts_list = []
        position = 4
        for i in range(num_of_ts):
            ts_type = data[position]
            protocol_id = data[position + 1]
            start_port, end_port = struct.unpack("!H", data[position + 4 : position + 6])[0], struct.unpack("!H", data[position + 6 : position + 8])[0]
            if ts_type == TS_IPV4_ADDR_RANGE:
                starting_address = socket.inet_ntop(socket.AF_INET, data[position + 8 : position + 12])
                ending_address = socket.inet_ntop(socket.AF_INET, data[position + 12 : position + 16])
                position += 16
            elif ts_type == TS_IPV6_ADDR_RANGE:
                starting_address = socket.inet_ntop(socket.AF_INET6, data[position + 8 : position + 24])
                ending_address = socket.inet_ntop(socket.AF_INET6, data[position + 24 : position + 40])
                position += 40

            ts_list.append((ts_type, protocol_id, start_port, end_port, starting_address, ending_address))
        return [num_of_ts, ts_list]

    ######### CIPHERED PAYLOAD ######
    ######### CIPHERED PAYLOAD ######
    ######### CIPHERED PAYLOAD ######
    def decode_payload_type_sk(self, data):
        if self.negotiated_encryption_algorithm in (ENCR_AES_CBC,):
            vector = data[0:16]
            hash_size = self.integ_key_truncated_len_bytes.get(self.negotiated_integrity_algorithm)
            hash_data = data[-hash_size:]

            encrypted_data = data[16 : len(data) - hash_size]

            if self.ike_decoded_header["flags"][2] == ROLE_RESPONDER:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_ER_old), modes.CBC(vector))
                else:
                    cipher = Cipher(algorithms.AES(self.SK_ER), modes.CBC(vector))
            else:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_EI_old), modes.CBC(vector))
                else:
                    cipher = Cipher(algorithms.AES(self.SK_EI), modes.CBC(vector))

            decryptor = cipher.decryptor()

            uncipher_data = decryptor.update(encrypted_data) + decryptor.finalize()

            padding_length = uncipher_data[-1]
            ike_payload = uncipher_data[0 : -padding_length - 1]

            (result_ok, decoded_payload) = self.decode_payload(ike_payload, self.current_next_payload, 0)
            if result_ok == True:
                return decoded_payload

        elif self.negotiated_encryption_algorithm in (ENCR_NULL,):
            hash_size = self.integ_key_truncated_len_bytes.get(self.negotiated_integrity_algorithm)
            hash_data = data[-hash_size:]

            ike_payload = data[0 : len(data) - hash_size - self.sk_ENCR_NULL_pad_length]
            (result_ok, decoded_payload) = self.decode_payload(ike_payload, self.current_next_payload, 0)
            if result_ok == True:
                return decoded_payload

    def decode_payload_type_cp(self, data):
        cfg_type = data[0]
        attribute_list = []
        position = 4
        while position < len(data):
            attribute_type = struct.unpack("!H", data[position : position + 2])[0]
            length = struct.unpack("!H", data[position + 2 : position + 4])[0]
            attribute_value = b""
            if length > 0:
                att_len = self.configuration_payload_len_bytes.get(attribute_type)
                if att_len == 4:  # ip
                    attribute_value = socket.inet_ntop(socket.AF_INET, data[position + 4 : position + 8])
                    attribute_list.append((attribute_type, attribute_value))
                elif att_len == 8:  # ip /netmask
                    attribute_value_1 = socket.inet_ntop(socket.AF_INET, data[position + 4 : position + 8])
                    attribute_value_2 = socket.inet_ntop(socket.AF_INET, data[position + 8 : position + 12])
                    attribute_list.append((attribute_type, attribute_value_1, attribute_value_2))
                elif att_len == 16:  # ipv6
                    attribute_value = socket.inet_ntop(socket.AF_INET6, data[position + 4 : position + 20])
                    attribute_list.append((attribute_type, attribute_value))
                elif att_len == 17:  # ipv6 + prefix
                    attribute_value_1 = socket.inet_ntop(socket.AF_INET6, data[position + 4 : position + 20])
                    attribute_value_2 = data[position + 21]
                    attribute_list.append((attribute_type, attribute_value_1, attribute_value_2))
                else:
                    attribute_value = data[position + 4 : position + 4 + length]
                    attribute_list.append((attribute_type, attribute_value))
            else:
                attribute_list.append((attribute_type, attribute_value))
            position += length + 4
        return [cfg_type, attribute_list]

    def decode_payload_type_eap(self, data):
        code = data[0]  # 1- request, 2-response, 3-success, 4-failure
        identifier = data[1]
        if code in (EAP_SUCCESS, EAP_FAILURE):
            return [code, identifier]
        elif code in (EAP_REQUEST, EAP_RESPONSE):
            if data[4] == EAP_AKA:
                return [code, identifier, data[4], data[5], self.decode_eap_attributes(data[8:])]  # code, identifier, type, sub type, [attributes list]
            else:
                return [code, identifier, data[4], data[5:]]
        else:
            return []

    def unsupported_payload_type(self, data):
        return None

    def decode_eap_attributes(self, data):
        eap_aka_decoded = []
        position = 0
        while position < len(data):
            attribute = data[position]
            if attribute in (AT_PERMANENT_ID_REQ, AT_ANY_ID_REQ, AT_FULLAUTH_ID_REQ, AT_RESULT_IND, AT_COUNTER, AT_COUNTER_TOO_SMALL, AT_CLIENT_ERROR_CODE, AT_NOTIFICATION):
                eap_aka_decoded.append((attribute, struct.unpack("!H", data[position + 2 : position + 4])[0]))
            elif attribute in (AT_IDENTITY, AT_RES, AT_NEXT_PSEUDONYM, AT_NEXT_REAUTH_ID):
                eap_aka_decoded.append((attribute, data[position + 4 : position + 4 + struct.unpack("!H", data[position + 2 : position + 4])[0]]))
            elif attribute in (AT_RAND, AT_AUTN, AT_IV, AT_MAC, AT_NONCE_S):
                eap_aka_decoded.append((attribute, data[position + 4 : position + 20]))
            elif attribute in (AT_AUTS,):
                eap_aka_decoded.append((attribute, data[position + 2 : position + 16]))
            elif attribute in (AT_CHECKCODE,):
                if data[position + 1] == 0:
                    eap_aka_decoded.append((attribute, struct.unpack("!H", data[position + 2 : position + 4])[0]))
                else:
                    eap_aka_decoded.append((attribute, data[position + 4 : position + 24]))

            elif attribute in (AT_ENCR_DATA,):
                eap_aka_decoded.append((attribute, data[position + 4 : position + 4 * data[position + 1]]))

            elif attribute in (AT_PADDING,):
                eap_aka_decoded.append((attribute, data[position + 2 : position + 4 * data[position + 1]]))

            position += data[position + 1] * 4
        return eap_aka_decoded

    #######################################################################################################################
    #######################################################################################################################
    ################                           E N C O D E     F U N C T I O N S                           ################
    #######################################################################################################################
    #######################################################################################################################

    def set_sa_list(self, sa_list):
        self.sa_list = sa_list

    def set_sa_list_child(self, sa_list):
        self.sa_list_child = sa_list

    def set_ts_list(self, type, ts_list):
        if type == TSI:
            self.ts_list_initiator = ts_list
        if type == TSR:
            self.ts_list_responder = ts_list

    def set_cp_list(self, cp_list):
        self.cp_list = cp_list

    def set_identification(self, payload_type, id_type, value):
        if payload_type == IDI:
            self.identification_initiator = (id_type, value)
        if payload_type == IDR:
            self.identification_responder = (id_type, value)

    def set_ike_packet_length(self, packet):
        packet = bytearray(packet)
        packet[24:28] = struct.pack("!I", len(packet))
        return packet

    def encode_header(self, initiator_spi, responder_spi, next_payload, major_version, minor_version, exchange_type, flags, message_id, length=0):
        header = b""
        header += initiator_spi
        header += responder_spi
        header += bytes([next_payload])
        header += bytes([major_version * 16 + minor_version])
        header += bytes([exchange_type])
        header += bytes([self.return_flags(flags)])
        header += struct.pack("!I", message_id)
        header += struct.pack("!I", length)
        return header

    def encode_generic_payload_header(self, next_payload, c, data):
        payload = b""
        payload += bytes([next_payload])
        payload += bytes([c * 128])
        payload += struct.pack("!H", len(data) + 4)
        payload += data
        return payload

    def encode_payload_type_sa(self, sa_list):
        payload_sa = b""
        proposal_list = []
        self.sa_spi_list = []
        m = 0

        proposal = 1
        for i in sa_list:
            transform_list = []

            protocol_id = i[0][0]
            spi_size = i[0][1]
            spi_bytes = self.return_random_bytes(spi_size)
            self.sa_spi_list.append(spi_bytes)

            for m in range(1, len(i)):  # transform_list

                transform_type = i[m][0]
                transform_id = i[m][1]
                if len(i[m]) == 3:  # attributes
                    attribute_type = i[m][2][0][0]
                    attribute_format = i[m][2][0][1]
                    attribute_value = i[m][2][1]
                    if attribute_format == 0:  # TLV: Value in bytes format
                        attribute_bytes = struct.pack("!H", attribute_type)
                        attribute_bytes += struct.pack("!H", len(attribute_value))
                        attribute_bytes += attribute_value
                    else:  # TV
                        attribute_bytes = struct.pack("!H", 32768 + attribute_type)
                        attribute_bytes += struct.pack("!H", attribute_value)
                else:
                    attribute_bytes = b""

                if proposal == 1 and transform_type == D_H and protocol_id == IKE:
                    self.dh_create_private_key_and_public_bytes(self.iana_diffie_hellman.get(transform_id))
                    self.dh_group_num = transform_id

                last = 3
                if m == len(i) - 1:
                    last = 0  # last transform

                transform_bytes = bytes([last]) + b"\x00\x00\x00" + bytes([transform_type]) + b"\x00" + struct.pack("!H", transform_id) + attribute_bytes
                transform_bytes = bytearray(transform_bytes)
                transform_bytes[2:4] = struct.pack("!H", len(transform_bytes))

                transform_list.append(transform_bytes)

            last = 2
            if proposal == len(sa_list):
                last = 0  # last proposal

            proposal_bytes = bytes([last]) + b"\x00\x00\x00" + bytes([proposal]) + bytes([protocol_id]) + bytes([spi_size]) + bytes([m]) + spi_bytes + b"".join(transform_list)

            proposal_bytes = bytearray(proposal_bytes)
            proposal_bytes[2:4] = struct.pack("!H", len(proposal_bytes))

            proposal_list.append(proposal_bytes)

            proposal += 1

        return b"".join(proposal_list)

    def encode_payload_type_ke(self):
        payload_ke = struct.pack("!H", self.dh_group_num) + b"\x00\x00" + self.dh_public_key_bytes
        return payload_ke

    def encode_payload_type_ninr(self, lowest=0):
        if lowest == 0:
            payload_ninr = self.return_random_bytes(16)
        elif lowest == -1:
            payload_ninr = b"\x00" * 8 + self.return_random_bytes(8)
        elif lowest == 1:
            payload_ninr = b"\xff" * 8 + self.return_random_bytes(8)
        self.nounce = payload_ninr
        return payload_ninr

    def encode_payload_type_tsi(self):
        return self.encode_payload_type_ts(TSI)

    def encode_payload_type_tsr(self):
        return self.encode_payload_type_ts(TSR)

    def encode_payload_type_ts(self, type):
        if type == TSI:
            ts_list = self.ts_list_initiator
        if type == TSR:
            ts_list = self.ts_list_responder

        payload_ts = bytes([len(ts_list)]) + b"\x00\x00\x00"

        for i in ts_list:
            ts_type = bytes([i[0]])
            ip_protocol = bytes([i[1]])
            start_port = struct.pack("!H", i[2])
            end_port = struct.pack("!H", i[3])
            if i[0] == TS_IPV4_ADDR_RANGE:
                length = struct.pack("!H", 16)
                starting_address = socket.inet_pton(socket.AF_INET, i[4])
                ending_address = socket.inet_pton(socket.AF_INET, i[5])
            elif i[0] == TS_IPV6_ADDR_RANGE:
                length = struct.pack("!H", 40)
                starting_address = socket.inet_pton(socket.AF_INET6, i[4])
                ending_address = socket.inet_pton(socket.AF_INET6, i[5])
            payload_ts += ts_type + ip_protocol + length + start_port + end_port + starting_address + ending_address

        return payload_ts

    def encode_payload_type_cp(self):

        payload_cp = bytes([self.cp_list[0]]) + b"\x00\x00\x00"
        for i in self.cp_list[1:]:
            if len(i) == 1:  # no value
                payload_cp += struct.pack("!H", i[0]) + b"\x00\x00"
            else:
                length = self.configuration_payload_len_bytes.get(i[0])
                if length == 4:  # ip address
                    value = socket.inet_pton(socket.AF_INET, i[1])
                    payload_cp += struct.pack("!H", i[0]) + struct.pack("!H", 4) + value
                elif length == 8:  # ip address, netmask
                    value_1, value_2 = socket.inet_pton(socket.AF_INET, i[1]), socket.inet_pton(socket.AF_INET, i[2])
                    payload_cp += struct.pack("!H", i[0]) + struct.pack("!H", 8) + value_1 + value_2
                elif length == 16:  # ipv6 address
                    value = socket.inet_pton(socket.AF_INET6, i[1])
                    payload_cp += struct.pack("!H", i[0]) + struct.pack("!H", 16) + value
                elif length == 17:  # ipv6 address, mask length
                    value = socket.inet_pton(socket.AF_INET6, i[1])
                    payload_cp += struct.pack("!H", i[0]) + struct.pack("!H", 17) + value + bytes([i[2]])
                else:  # not stricted
                    payload_cp += struct.pack("!H", i[0]) + struct.pack("!H", len(i[1])) + i[1]

        return payload_cp

    def encode_payload_type_idi(self):
        return self.encode_payload_type_id(IDI)

    def encode_payload_type_idr(self):
        return self.encode_payload_type_id(IDR)

    def encode_payload_type_id(self, type):  # id
        if type == IDI:
            (id_type, value) = self.identification_initiator
        if type == IDR:
            (id_type, value) = self.identification_responder
        if id_type in (ID_FQDN, ID_RFC822_ADDR):
            value = value.encode("utf-8")
        elif id_type == ID_IPV4_ADDR:
            value = socket.inet_pton(socket.AF_INET, value)
        elif id_type == ID_IPV6_ADDR:
            value = socket.inet_pton(socket.AF_INET6, value)
        # else binary, so use value as is.
        payload_id = bytes([id_type]) + b"\x00\x00\x00" + value

        return payload_id

    def encode_payload_type_eap(self):
        return self.eap_payload_response

    def encode_payload_type_auth(self, auth_method):
        return bytes([auth_method]) + b"\x00" * 3 + self.AUTH_payload

    def encode_payload_type_d(self, protocol, spi_list=b""):
        if protocol == IKE:
            return bytes([IKE]) + b"\x00\x00\x00"
        elif protocol == ESP:
            num_spi = len(spi_list) // 4
            return bytes([ESP]) + b"\x04" + struct.pack("!H", num_spi) + spi_list

    def encode_payload_type_n(self, protocol, spi, notify_message_type, notification_data=b""):
        spi_size = len(spi)
        return bytes([protocol]) + bytes([spi_size]) + struct.pack("!H", notify_message_type) + spi + notification_data

    def encode_payload_type_sk(self, ike_packet):

        hash_size = self.integ_key_truncated_len_bytes.get(self.negotiated_integrity_algorithm)

        if self.negotiated_encryption_algorithm in (ENCR_AES_CBC,):
            vector = self.return_random_bytes(16)
            data_to_encrypt = ike_packet[28:]

            res = 16 - (len(data_to_encrypt) % 16)
            if res > 1:
                data_to_encrypt += b"\x00" * (res - 1) + bytes([res - 1])
            else:
                data_to_encrypt += b"\x00" * (15 + res) + bytes([15 + res])

            flags_role = self.return_flags(ike_packet[19])[2]

            if flags_role == ROLE_INITIATOR:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_EI_old), modes.CBC(vector))
                else:
                    cipher = Cipher(algorithms.AES(self.SK_EI), modes.CBC(vector))
            else:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_ER_old), modes.CBC(vector))
                else:
                    cipher = Cipher(algorithms.AES(self.SK_ER), modes.CBC(vector))

            encryptor = cipher.encryptor()
            cipher_data = encryptor.update(data_to_encrypt) + encryptor.finalize()

            sk_payload = self.encode_generic_payload_header(ike_packet[16], 0, vector + cipher_data + b"\x00" * hash_size)  # add a dummy hash to calculate correct length
            new_ike_packet = ike_packet[0:16] + bytes([SK]) + ike_packet[17:28] + sk_payload
            new_ike_packet = self.set_ike_packet_length(new_ike_packet)
            new_ike_packet_to_integrity = new_ike_packet[0:-hash_size]
            hash = self.integ_function.get(self.negotiated_integrity_algorithm)

            if flags_role == ROLE_INITIATOR:
                if self.old_ike_message_received == True:
                    h = hmac.HMAC(self.SK_AI_old, hash)
                else:
                    h = hmac.HMAC(self.SK_AI, hash)
            else:
                if self.old_ike_message_received == True:
                    h = hmac.HMAC(self.SK_AR_old, hash)
                else:
                    h = hmac.HMAC(self.SK_AR, hash)

            h.update(new_ike_packet_to_integrity)
            hash = h.finalize()[0:hash_size]

            return new_ike_packet_to_integrity + hash

        elif self.negotiated_encryption_algorithm in (ENCR_NULL,):

            data_to_encrypt = ike_packet[28:]

            sk_payload = self.encode_generic_payload_header(ike_packet[16], 0, data_to_encrypt + b"\x00" * (hash_size + self.sk_ENCR_NULL_pad_length))
            new_ike_packet = ike_packet[0:16] + bytes([SK]) + ike_packet[17:28] + sk_payload
            new_ike_packet = self.set_ike_packet_length(new_ike_packet)
            new_ike_packet_to_integrity = new_ike_packet[0:-hash_size]
            hash = self.integ_function.get(self.negotiated_integrity_algorithm)

            flags_role = self.return_flags(ike_packet[19])[2]
            if flags_role == ROLE_INITIATOR:
                if self.old_ike_message_received == True:
                    h = hmac.HMAC(self.SK_AI_old, hash)
                else:
                    h = hmac.HMAC(self.SK_AI, hash)
            else:
                if self.old_ike_message_received == True:
                    h = hmac.HMAC(self.SK_AR_old, hash)
                else:
                    h = hmac.HMAC(self.SK_AR, hash)

            h.update(new_ike_packet_to_integrity)
            hash = h.finalize()[0:hash_size]

            return new_ike_packet_to_integrity + hash

    #######################################################################################################################
    #######################################################################################################################
    ############                    S T A T E    &    M E S S A G E S     F U N C T I O N S                    ############
    #######################################################################################################################
    #######################################################################################################################

    ### USER PLANE FUNCTIONS AND INTER PROCESS COMMUNICATION ####
    def set_routes(self):
        # Fake using a pipe
        r, w = os.pipe()
        self.tunnel = w

    def delete_routes(self):
        pass

    def esp_padding(self, length):
        padding = b""
        for i in range(length):
            padding += bytes([i + 1])
        return padding

    def encapsulate_esp_packet(self, packet, encr_alg, encr_key, integ_alg, integ_key, spi_resp, sqn):

        hash_size = self.integ_key_truncated_len_bytes.get(integ_alg)
        if packet[0] // 16 == 4:  # ipv4
            packet_type = 4
        elif packet[0] // 16 == 6:  # ipv6
            packet_type = 41
        else:
            return None

        if encr_alg in (ENCR_AES_CBC,):
            vector = self.return_random_bytes(16)
            data_to_encrypt = packet

            res = 16 - (len(data_to_encrypt) % 16)
            if res > 1:
                data_to_encrypt += self.esp_padding(res - 2) + bytes([res - 2]) + bytes([packet_type])
            else:
                data_to_encrypt += self.esp_padding(14 + res) + bytes([14 + res]) + bytes([packet_type])

            cipher = Cipher(algorithms.AES(encr_key), modes.CBC(vector))
            encryptor = cipher.encryptor()
            cipher_data = encryptor.update(data_to_encrypt) + encryptor.finalize()

            new_ike_packet = spi_resp + struct.pack("!I", sqn) + vector + cipher_data

            if hash_size != 0:
                hash = self.integ_function.get(integ_alg)
                h = hmac.HMAC(integ_key, hash)
                h.update(new_ike_packet)
                hash = h.finalize()[0:hash_size]
            else:
                hash = b""

            return new_ike_packet + hash

        elif encr_alg in (ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16):

            if encr_alg == ENCR_AES_GCM_8:
                mac_length = 8
            if encr_alg == ENCR_AES_GCM_12:
                mac_length = 12
            if encr_alg == ENCR_AES_GCM_16:
                mac_length = 16

            aad = spi_resp + struct.pack("!I", sqn)
            vector = self.return_random_bytes(8)

            data_to_encrypt = packet

            res = (len(data_to_encrypt) + 2) % 4
            if res == 0:
                data_to_encrypt += bytes([res]) + bytes([packet_type])
            else:
                data_to_encrypt += self.esp_padding(4 - res) + bytes([4 - res]) + bytes([packet_type])

            cipher = AES.new(encr_key[:-4], AES.MODE_GCM, nonce=encr_key[-4:] + vector, mac_len=mac_length)
            cipher.update(aad)

            cipher_data, tag = cipher.encrypt_and_digest(data_to_encrypt)

            new_ike_packet = spi_resp + struct.pack("!I", sqn) + vector + cipher_data + tag

            return new_ike_packet

        elif encr_alg in (ENCR_NULL,):

            new_ike_packet = spi_resp + struct.pack("!I", sqn) + packet + bytes([0]) + bytes([packet_type])

            if hash_size != 0:
                hash = self.integ_function.get(integ_alg)
                h = hmac.HMAC(integ_key, hash)
                h.update(new_ike_packet)
                hash = h.finalize()[0:hash_size]
            else:
                hash = b""

            return new_ike_packet + hash

        return None

    def encapsulate_ipsec(self, args):

        pipe_ike = args[0]
        socket_list = [self.tunnel, pipe_ike, self.socket_esp]
        encr_alg = None
        integ_alg = None
        sqn = 1

        while True:
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for sock in read_sockets:
                if sock == self.tunnel:
                    tap_packet = os.read(self.tunnel, 1514)

                    if encr_alg is not None:

                        encrypted_packet = self.encapsulate_esp_packet(tap_packet, encr_alg, encr_key, integ_alg, integ_key, spi_resp, sqn)
                        if encrypted_packet is not None:
                            sqn += 1
                            if self.userplane_mode == ESP_PROTOCOL:
                                self.socket_esp.sendto(encrypted_packet, self.server_address_esp)
                            else:
                                self.socket_nat.sendto(encrypted_packet, self.server_address_nat)

                elif sock == pipe_ike:
                    pipe_packet = pipe_ike.recv()
                    decode_list = self.decode_inter_process_protocol(pipe_packet)
                    if decode_list[0] == INTER_PROCESS_DELETE_SA:
                        sys.exit()
                    elif decode_list[0] in (INTER_PROCESS_CREATE_SA, INTER_PROCESS_UPDATE_SA):
                        for i in decode_list[1]:
                            if i[0] == INTER_PROCESS_IE_ENCR_ALG:
                                encr_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_ALG:
                                integ_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_ENCR_KEY:
                                encr_key = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_KEY:
                                integ_key = i[1]
                            if i[0] == INTER_PROCESS_IE_SPI_RESP:
                                spi_resp = i[1]
                    elif decode_list[0] == INTER_PROCESS_IKE and decode_list[1][0] == INTER_PROCESS_IE_IKE_MESSAGE:  # not used for now. check 4 bytes zero if nat transversal
                        ike_message = decode_list[1][1]
                        self.socket_nat.sendto(ike_message, self.server_address_nat)

        return 0

    def decapsulate_ipsec(self, args):

        pipe_ike = args[0]

        socket_list = [self.socket_nat, pipe_ike, self.socket_esp]
        encr_alg = None
        integ_alg = None

        while True:
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for sock in read_sockets:
                if sock == self.socket_nat:
                    packet, address = self.socket_nat.recvfrom(2000)

                    if encr_alg is not None:
                        if packet[0:4] == b"\x00\x00\x00\x00":  # is ike message
                            inter_process_list_ike_message = [INTER_PROCESS_IKE, [(INTER_PROCESS_IE_IKE_MESSAGE, packet)]]
                            pipe_ike.send(self.encode_inter_process_protocol(inter_process_list_ike_message))

                        elif packet[0:4] == spi_init:

                            if encr_alg is not None:
                                decrypted_packet = self.decapsulate_esp_packet(packet, encr_alg, encr_key, integ_alg, integ_key)
                                if decrypted_packet is not None:

                                    os.write(self.tunnel, decrypted_packet)

                elif sock == self.socket_esp:
                    packet, address = self.socket_esp.recvfrom(2000)
                    if encr_alg is not None:
                        if packet[20:24] == spi_init:

                            if encr_alg is not None:
                                decrypted_packet = self.decapsulate_esp_packet(packet[20:], encr_alg, encr_key, integ_alg, integ_key)
                                if decrypted_packet is not None:

                                    os.write(self.tunnel, decrypted_packet)

                elif sock == pipe_ike:
                    pipe_packet = pipe_ike.recv()
                    decode_list = self.decode_inter_process_protocol(pipe_packet)
                    if decode_list[0] == INTER_PROCESS_DELETE_SA:
                        sys.exit()
                    elif decode_list[0] in (INTER_PROCESS_CREATE_SA, INTER_PROCESS_UPDATE_SA):
                        for i in decode_list[1]:
                            if i[0] == INTER_PROCESS_IE_ENCR_ALG:
                                encr_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_ALG:
                                integ_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_ENCR_KEY:
                                encr_key = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_KEY:
                                integ_key = i[1]
                            if i[0] == INTER_PROCESS_IE_SPI_INIT:
                                spi_init = i[1]

        return 0

    def decapsulate_esp_packet(self, packet, encr_alg, encr_key, integ_alg, integ_key):

        if encr_alg in (ENCR_AES_CBC,):
            vector = packet[8:24]
            hash_size = self.integ_key_truncated_len_bytes.get(integ_alg)
            hash_data = packet[-hash_size:]

            encrypted_data = packet[24 : len(packet) - hash_size]

            cipher = Cipher(algorithms.AES(encr_key), modes.CBC(vector))
            decryptor = cipher.decryptor()

            uncipher_data = decryptor.update(encrypted_data) + decryptor.finalize()
            padding_length = uncipher_data[-2]
            uncipher_packet = uncipher_data[0 : -padding_length - 2]

            return uncipher_packet

        elif encr_alg in (ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16):
            if encr_alg == ENCR_AES_GCM_8:
                mac_length = 8
            if encr_alg == ENCR_AES_GCM_12:
                mac_length = 12
            if encr_alg == ENCR_AES_GCM_16:
                mac_length = 16

            aad = packet[0:8]
            cipher = AES.new(encr_key[:-4], AES.MODE_GCM, nonce=encr_key[-4:] + packet[8:16], mac_len=mac_length)
            cipher.update(aad)

            uncipher_data = cipher.decrypt_and_verify(packet[16:-mac_length], packet[-mac_length:])
            padding_length = uncipher_data[-2]
            uncipher_packet = uncipher_data[0 : -padding_length - 2]

            return uncipher_packet

        elif encr_alg in (ENCR_NULL,):
            hash_size = self.integ_key_truncated_len_bytes.get(integ_alg)
            hash_data = packet[-hash_size:]

            uncipher_data = packet[8 : len(packet) - hash_size]
            padding_length = uncipher_data[-2]
            uncipher_packet = uncipher_data[0 : -padding_length - 2]

            return uncipher_packet

        return None

    def decode_inter_process_protocol(self, packet):
        try:
            ie_list = []
            message = packet[0]
            position = 3
            while position < len(packet):
                if packet[position + 1] == 0 and packet[position + 2] == 1:
                    ie_list.append((packet[position], packet[position + 3]))
                else:
                    ie_list.append((packet[position], packet[position + 3 : position + 3 + packet[position + 1] * 256 + packet[position + 2]]))
                position += 3 + packet[position + 1] * 256 + packet[position + 2]
            return [message, ie_list]
        except:
            return [None, None]

    def encode_inter_process_protocol(self, message):
        packet = b""
        for i in message[1]:
            if type(i[1]) is int:
                packet += bytes([i[0]]) + b"\x00\x01" + bytes([i[1]])
            else:
                packet += bytes([i[0]]) + struct.pack("!H", len(i[1])) + i[1]

        packet = bytes([message[0]]) + struct.pack("!H", len(packet)) + packet
        return packet

    #### AUX FUNCTIONS RELATED TO STATES OR MESSAGES

    def get_eap_aka_attribute_value(self, list, id):
        for i in list:
            if i[0] == id:
                return i[1]
        return None

    def get_cp_attribute_value(self, list, id):
        return_list = []
        for i in list:
            if i[0] == id:
                return_list.append(i[1])
        return return_list

    def set_sa_negotiated(self, num):
        sa_negotiated = self.sa_list[num - 1]
        self.sa_list_negotiated = [self.sa_list[num - 1]]

        # default values
        self.negotiated_integrity_algorithm = NONE
        self.negotiated_encryption_algorithm = ENCR_NULL
        self.negotiated_encryption_algorithm_key_size = 0

        for i in sa_negotiated[1:]:
            if i[0] == ENCR:
                self.negotiated_encryption_algorithm = i[1]
                if self.negotiated_encryption_algorithm != ENCR_NULL:
                    self.negotiated_encryption_algorithm_key_size = i[2][1]
            if i[0] == PRF:
                self.negotiated_prf = i[1]
            if i[0] == INTEG:
                self.negotiated_integrity_algorithm = i[1]
            if i[0] == D_H:
                self.negotiated_diffie_hellman_group = i[1]

    def remove_sa_from_list(self, accepted_dh_group):
        new_sa_list = []
        for p in self.sa_list:
            for i in p:
                if i[0] == D_H and i[1] == accepted_dh_group:
                    new_sa_list.append(p)
                    break
        self.sa_list = new_sa_list

    def set_sa_negotiated_child(self, num):
        sa_negotiated = self.sa_list_child[num - 1]
        self.spi_init_child = self.sa_spi_list[num - 1]
        self.sa_list_negotiated_child = [self.sa_list_child[num - 1]]

        # default values
        self.negotiated_integrity_algorithm_child = NONE
        self.negotiated_encryption_algorithm_child = ENCR_NULL
        self.negotiated_encryption_algorithm_key_size_child = 0

        for i in sa_negotiated[1:]:
            if i[0] == ENCR:
                self.negotiated_encryption_algorithm_child = i[1]
                if self.negotiated_encryption_algorithm_child != ENCR_NULL:
                    self.negotiated_encryption_algorithm_key_size_child = i[2][1]
            if i[0] == ESN:
                self.negotiated_esn_child = i[1]
            if i[0] == INTEG:
                self.negotiated_integrity_algorithm_child = i[1]
            if i[0] == D_H:
                self.negotiated_diffie_hellman_group_child = i[1]

    def generate_keying_material_child(self):

        STREAM = self.nounce + self.nounce_received

        AUTH_KEY_SIZE = self.integ_key_len_bytes.get(self.negotiated_integrity_algorithm_child)
        ENCR_KEY_SIZE = self.negotiated_encryption_algorithm_key_size_child // 8

        # exception for GCM since we need extra 4 bytes for SALT
        if self.negotiated_encryption_algorithm_child in (ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16):
            ENCR_KEY_SIZE += 4

        KEY_LENGHT_TOTAL = 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE
        KEYMAT = self.prf_plus(self.negotiated_prf, self.SK_D, STREAM, KEY_LENGHT_TOTAL)

        self.SK_IPSEC_EI = KEYMAT[0:ENCR_KEY_SIZE]
        self.SK_IPSEC_AI = KEYMAT[ENCR_KEY_SIZE : ENCR_KEY_SIZE + AUTH_KEY_SIZE]
        self.SK_IPSEC_ER = KEYMAT[ENCR_KEY_SIZE + AUTH_KEY_SIZE : 2 * ENCR_KEY_SIZE + AUTH_KEY_SIZE]
        self.SK_IPSEC_AR = KEYMAT[2 * ENCR_KEY_SIZE + AUTH_KEY_SIZE : 2 * ENCR_KEY_SIZE + 2 * AUTH_KEY_SIZE]

        print("SK_IPSEC_AI", toHex(self.SK_IPSEC_AI))
        print("SK_IPSEC_AR", toHex(self.SK_IPSEC_AR))
        print("SK_IPSEC_EI", toHex(self.SK_IPSEC_EI))
        print("SK_IPSEC_ER", toHex(self.SK_IPSEC_ER))

        self.print_esp_sa()

    def generate_keying_material(self):

        hash = self.prf_function.get(self.negotiated_prf)
        h = hmac.HMAC(self.nounce + self.nounce_received, hash)
        h.update(self.dh_shared_key)
        SKEYSEED = h.finalize()
        print("SKEYSEED", toHex(SKEYSEED))

        STREAM = self.nounce + self.nounce_received + self.ike_spi_initiator + self.ike_spi_responder
        print("STREAM", toHex(STREAM))

        PRF_KEY_SIZE = self.prf_key_len_bytes.get(self.negotiated_prf)
        AUTH_KEY_SIZE = self.integ_key_len_bytes.get(self.negotiated_integrity_algorithm)
        ENCR_KEY_SIZE = self.negotiated_encryption_algorithm_key_size // 8

        KEY_LENGHT_TOTAL = 3 * PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE

        KEY_STREAM = self.prf_plus(self.negotiated_prf, SKEYSEED, STREAM, KEY_LENGHT_TOTAL)

        self.SK_D = KEY_STREAM[0:PRF_KEY_SIZE]
        self.SK_AI = KEY_STREAM[PRF_KEY_SIZE : PRF_KEY_SIZE + AUTH_KEY_SIZE]
        self.SK_AR = KEY_STREAM[PRF_KEY_SIZE + AUTH_KEY_SIZE : PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE]
        self.SK_EI = KEY_STREAM[PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE : PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + ENCR_KEY_SIZE]
        self.SK_ER = KEY_STREAM[PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + ENCR_KEY_SIZE : PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE]
        self.SK_PI = KEY_STREAM[PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE : 2 * PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE]
        self.SK_PR = KEY_STREAM[2 * PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE : 3 * PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE]

        print("SK_D", toHex(self.SK_D))
        print("SK_AI", toHex(self.SK_AI))
        print("SK_AR", toHex(self.SK_AR))
        print("SK_EI", toHex(self.SK_EI))
        print("SK_ER", toHex(self.SK_ER))
        print("SK_PI", toHex(self.SK_PI))
        print("SK_PR", toHex(self.SK_PR))

        self.print_ikev2_decryption_table()

    def generate_new_ike_keying_material(self):

        self.SK_D_old = self.SK_D
        self.SK_AI_old = self.SK_AI
        self.SK_AR_old = self.SK_AR
        self.SK_EI_old = self.SK_EI
        self.SK_ER_old = self.SK_ER
        self.SK_PI_old = self.SK_PI
        self.SK_PR_old = self.SK_PR

        hash = self.prf_function.get(self.negotiated_prf)
        h = hmac.HMAC(self.SK_D, hash)
        h.update(self.dh_shared_key + self.nounce + self.nounce_received)
        SKEYSEED = h.finalize()
        print("SKEYSEED", toHex(SKEYSEED))

        STREAM = self.nounce + self.nounce_received + self.ike_spi_initiator + self.ike_spi_responder

        print("STREAM", toHex(STREAM))
        PRF_KEY_SIZE = self.prf_key_len_bytes.get(self.negotiated_prf)
        AUTH_KEY_SIZE = self.integ_key_len_bytes.get(self.negotiated_integrity_algorithm)
        ENCR_KEY_SIZE = self.negotiated_encryption_algorithm_key_size // 8

        KEY_LENGHT_TOTAL = PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE

        KEY_STREAM = self.prf_plus(self.negotiated_prf, SKEYSEED, STREAM, KEY_LENGHT_TOTAL)

        self.SK_D = KEY_STREAM[0:PRF_KEY_SIZE]
        self.SK_AI = KEY_STREAM[PRF_KEY_SIZE : PRF_KEY_SIZE + AUTH_KEY_SIZE]
        self.SK_AR = KEY_STREAM[PRF_KEY_SIZE + AUTH_KEY_SIZE : PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE]
        self.SK_EI = KEY_STREAM[PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE : PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + ENCR_KEY_SIZE]
        self.SK_ER = KEY_STREAM[PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + ENCR_KEY_SIZE : PRF_KEY_SIZE + 2 * AUTH_KEY_SIZE + 2 * ENCR_KEY_SIZE]

        print("SK_D", toHex(self.SK_D))
        print("SK_AI", toHex(self.SK_AI))
        print("SK_AR", toHex(self.SK_AR))
        print("SK_EI", toHex(self.SK_EI))
        print("SK_ER", toHex(self.SK_ER))

        self.print_ikev2_decryption_table()

    def prf_plus(self, algorithm, key, stream, size):
        hash = self.prf_function.get(algorithm)
        t = b""
        t_total = b""
        iter = 1
        while len(t_total) < size:
            h = hmac.HMAC(key, hash)
            h.update(t + stream + bytes([iter]))
            t = h.finalize()
            t_total += t
            iter += 1

        return t_total[0:size]

    def sha1_nat_source(self, print_info=True):
        digest = hashes.Hash(hashes.SHA1())
        if self.userplane_mode == ESP_PROTOCOL:
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET, self.source_address) + struct.pack("!H", self.port))
        else:  # NAT_TRAVERSAL
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET, self.source_address) + struct.pack("!H", self.port_nat))
        hash = digest.finalize()
        if print_info == True:
            print("NAT SOURCE", toHex(hash))
        return hash

    def sha1_nat_destination(self, print_info=True):
        digest = hashes.Hash(hashes.SHA1())
        if self.userplane_mode == ESP_PROTOCOL:
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET, self.epdg_address) + struct.pack("!H", self.port))
        else:  # NAT_TRAVERSAL
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET, self.epdg_address) + struct.pack("!H", self.port_nat))
        hash = digest.finalize()
        if print_info == True:
            print("NAT DESTINATION", toHex(hash))
        return hash

    #### MESSAGES ####

    def create_IKE_SA_INIT(self, same_spi=False, cookie=False):
        # create SPIi
        if same_spi == False:
            self.ike_spi_initiator = self.return_random_bytes(8)
        self.ike_spi_responder = (0).to_bytes(8, "big")
        if cookie == False:
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, IKE_SA_INIT, (0, 0, 1), self.message_id_request)
            payload = b""
        else:
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, N, 2, 0, IKE_SA_INIT, (0, 0, 1), self.message_id_request)
            payload = self.encode_generic_payload_header(SA, 0, self.encode_payload_type_n(RESERVED, b"", COOKIE, self.cookie_received_bytes))

        payload += self.encode_generic_payload_header(KE, 0, self.encode_payload_type_sa(self.sa_list))

        payload += self.encode_generic_payload_header(NINR, 0, self.encode_payload_type_ke())
        if self.check_nat == False:
            if cookie == True:
                payload += self.encode_generic_payload_header(NONE, 0, self.nounce)
            else:
                payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_ninr())
        else:
            if cookie == True:
                payload += self.encode_generic_payload_header(N, 0, self.nounce)
            else:
                payload += self.encode_generic_payload_header(N, 0, self.encode_payload_type_ninr())

            payload += self.encode_generic_payload_header(N, 0, self.encode_payload_type_n(RESERVED, b"", NAT_DETECTION_SOURCE_IP, self.sha1_nat_source()))
            payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_n(RESERVED, b"", NAT_DETECTION_DESTINATION_IP, self.sha1_nat_destination()))
        packet = self.set_ike_packet_length(header + payload)
        return packet

    def create_IKE_AUTH(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, IDI, 2, 0, IKE_AUTH, (0, 0, 1), self.message_id_request)
        payload = self.encode_generic_payload_header(IDR, 0, self.encode_payload_type_idi())
        payload += self.encode_generic_payload_header(CP, 0, self.encode_payload_type_idr())
        payload += self.encode_generic_payload_header(SA, 0, self.encode_payload_type_cp())
        payload += self.encode_generic_payload_header(TSI, 0, self.encode_payload_type_sa(self.sa_list_child))
        payload += self.encode_generic_payload_header(TSR, 0, self.encode_payload_type_tsi())
        payload += self.encode_generic_payload_header(N, 0, self.encode_payload_type_tsr())
        payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_n(RESERVED, b"", EAP_ONLY_AUTHENTICATION))
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_IKE_AUTH_EAP_IDENTITY(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, EAP, 2, 0, IKE_AUTH, (0, 0, 1), self.message_id_request)
        payload = self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_eap())
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_IKE_AUTH_2(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, EAP, 2, 0, IKE_AUTH, (0, 0, 1), self.message_id_request)
        payload = self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_eap())
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_IKE_AUTH_3(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, AUTH, 2, 0, IKE_AUTH, (0, 0, 1), self.message_id_request)
        payload = self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_auth(SHARED_KEY_MESSAGE_INTEGRITY_CODE))
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def answer_INFORMATIONAL_delete(self):
        if self.old_ike_message_received == True:
            header = self.encode_header(self.ike_spi_initiator_old, self.ike_spi_responder_old, NONE, 2, 0, INFORMATIONAL, (1, 0, 1), self.ike_decoded_header["message_id"])
        else:
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, NONE, 2, 0, INFORMATIONAL, (1, 0, 1), self.ike_decoded_header["message_id"])

        packet = self.set_ike_packet_length(header)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def answer_INFORMATIONAL_delete_CHILD(self, protocol, spi_list=b""):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, D, 2, 0, INFORMATIONAL, (1, 0, 1), self.ike_decoded_header["message_id"])

        payload = self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_d(protocol, spi_list))
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_INFORMATIONAL_delete(self, protocol, spi_list=b""):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, D, 2, 0, INFORMATIONAL, (0, 0, 1), self.message_id_request)

        payload = self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_d(protocol, spi_list))
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def answer_CREATE_CHILD_SA(self):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (1, 0, 1), self.ike_decoded_header["message_id"])

        payload = self.encode_generic_payload_header(KE, 0, self.encode_payload_type_sa(self.sa_list_create_child_sa))
        payload += self.encode_generic_payload_header(NINR, 0, self.encode_payload_type_ke())
        payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_ninr())
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def answer_NOTIFY_NO_PROPOSAL_CHOSEN(self):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, N, 2, 0, CREATE_CHILD_SA, (1, 0, 1), self.ike_decoded_header["message_id"])

        payload = self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_n(IKE, b"", NO_PROPOSAL_CHOSEN))
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_CREATE_CHILD_SA(self, lowest=0):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (0, 0, 1), self.message_id_request)

        payload = self.encode_generic_payload_header(KE, 0, self.encode_payload_type_sa(self.sa_list_create_child_sa))
        payload += self.encode_generic_payload_header(NINR, 0, self.encode_payload_type_ke())
        payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_ninr(lowest))
        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_CREATE_CHILD_SA_CHILD(self, lowest=0):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (0, 0, 1), self.message_id_request)

        payload = self.encode_generic_payload_header(NINR, 0, self.encode_payload_type_sa(self.sa_list_create_child_sa_child))
        payload += self.encode_generic_payload_header(N, 0, self.encode_payload_type_ninr(lowest))
        payload += self.encode_generic_payload_header(TSI, 0, self.encode_payload_type_n(ESP, self.spi_init_child, REKEY_SA))
        payload += self.encode_generic_payload_header(TSR, 0, self.encode_payload_type_tsi())
        payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_tsr())

        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def answer_CREATE_CHILD_SA_CHILD(self, lowest=0):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (1, 0, 1), self.ike_decoded_header["message_id"])

        payload = self.encode_generic_payload_header(NINR, 0, self.encode_payload_type_sa(self.sa_list_create_child_sa_child))
        payload += self.encode_generic_payload_header(N, 0, self.encode_payload_type_ninr(lowest))
        payload += self.encode_generic_payload_header(TSI, 0, self.encode_payload_type_n(ESP, self.spi_init_child, REKEY_SA))
        payload += self.encode_generic_payload_header(TSR, 0, self.encode_payload_type_tsi())
        payload += self.encode_generic_payload_header(NONE, 0, self.encode_payload_type_tsr())

        packet = self.set_ike_packet_length(header + payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    #### STATES ####

    def state_1(self, retry=False, cookie=False):  # Send IKE_SA_INIT and process answer
        self.message_id_request = 0

        packet = self.create_IKE_SA_INIT(retry, cookie)

        self.AUTH_SA_INIT_packet = packet  # needed for AUTH Payload in state 4

        self.send_data(packet)
        print("sending IKE_SA_INIT")

        try:
            # if True:
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True:
                        break
                else:
                    packet, address = self.socket_nat.recvfrom(2000)
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True:
                        break

        except:  # timeout
            return TIMEOUT, "TIMEOUT"

        if self.ike_decoded_header["exchange_type"] == IKE_SA_INIT:
            print("received IKE_SA_INIT")
            for i in self.decoded_payload:
                if i[0] == NINR:
                    self.nounce_received = i[1][0]

                elif i[0] == SA:
                    proposal = i[1][0]
                    protocol_id = i[1][1]
                    if protocol_id == IKE:
                        self.set_sa_negotiated(proposal)
                    else:
                        return MANDATORY_INFORMATION_MISSING, "MANDATORY_INFORMATION_MISSING"

                elif i[0] == KE:
                    dh_peer_public_key_bytes = i[1][1]
                    self.dh_calculate_shared_key(dh_peer_public_key_bytes)

                elif i[0] == N:  # protocol_id, notify_message_type, spi, notification_data
                    if i[1][1] == INVALID_KE_PAYLOAD:
                        accepted_dh_group = struct.unpack("!H", i[1][3])[0]
                        self.remove_sa_from_list(accepted_dh_group)
                        return REPEAT_STATE, "INVALID_KE_PAYLOAD"
                    elif i[1][1] < 16384:  # error
                        return OTHER_ERROR, str(i[1][1])

                    elif i[1][1] == COOKIE:
                        self.cookie = True
                        self.cookie_received_bytes = i[1][3]
                        return REPEAT_STATE_COOKIE, "REPEAT SA_INIT WITH COOKIE"

                    elif i[1][1] == NAT_DETECTION_DESTINATION_IP:
                        received_nat_detection_destination = i[1][3]
                        print("NAT DESTINATION RECEIVED", toHex(received_nat_detection_destination))
                        calculated_nat_detection_destination = self.sha1_nat_source(False)
                        print("NAT DESTINATION CALCULATED", toHex(calculated_nat_detection_destination))
                        if received_nat_detection_destination != calculated_nat_detection_destination:
                            self.userplane_mode = NAT_TRAVERSAL

                    elif i[1][1] == NAT_DETECTION_SOURCE_IP:
                        received_nat_detection_source = i[1][3]
                        print("NAT SOURCE RECEIVED", toHex(received_nat_detection_source))
                        calculated_nat_detection_source = self.sha1_nat_destination(False)
                        print("NAT SOURCE CALCULATED", toHex(calculated_nat_detection_source))
                        if received_nat_detection_source != calculated_nat_detection_source:
                            self.userplane_mode = NAT_TRAVERSAL

            self.generate_keying_material()

            print("IKE SPI INITIATOR", toHex(self.ike_spi_initiator))
            print("IKE SPI RESPONDER", toHex(self.ike_spi_responder))

            return OK, ""
        else:
            return DECODING_ERROR, "DECODING_ERROR"

    def state_2(self, retry=False):
        self.message_id_request += 1
        if retry == False:
            packet = self.create_IKE_AUTH()
        else:
            packet = self.create_IKE_AUTH_EAP_IDENTITY()
        self.send_data(packet)
        print("sending IKE_AUTH (1)")

        try:

            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True:
                        break
                else:
                    packet, address = self.socket_nat.recvfrom(2000)
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True:
                        break

        except:  # timeout
            return TIMEOUT, "TIMEOUT"

        eap_received = False
        if self.ike_decoded_header["exchange_type"] == IKE_AUTH and self.decoded_payload[0][0] == SK:
            print("received IKE_AUTH (1)")
            for i in self.decoded_payload[0][1]:

                if i[0] == N:  # protocol_id, notify_message_type, spi, notification_data
                    if i[1][1] == DEVICE_IDENTITY:
                        pass
                        # add imei in next auth

                    elif i[1][1] < 16384:  # error
                        return OTHER_ERROR, str(i[1][1])
                elif i[0] == EAP:

                    if i[1][0] in (EAP_REQUEST,) and i[1][2] in (EAP_AKA,):
                        if i[1][3] in (AKA_Challenge, AKA_Reauthentication):

                            eap_received = True

                            RAND = self.get_eap_aka_attribute_value(i[1][4], AT_RAND)
                            AUTN = self.get_eap_aka_attribute_value(i[1][4], AT_AUTN)
                            MAC = self.get_eap_aka_attribute_value(i[1][4], AT_MAC)

                            VECTOR = self.get_eap_aka_attribute_value(i[1][4], AT_IV)
                            ENCR_DATA = self.get_eap_aka_attribute_value(i[1][4], AT_ENCR_DATA)

                            self.eap_identifier = i[1][1]

                            if (RAND is not None and AUTN is not None) or (VECTOR is not None and ENCR_DATA is not None):
                                if RAND is not None and AUTN is not None:
                                    if self.sqn is not None and retry == False:
                                        raise Exception("Cannot process wat")
                                        auts = return_auts(toHex(RAND), toHex(AUTN), self.ki, self.op, self.opc, self.sqn)
                                        eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex("0018170400000404") + auts
                                        self.eap_payload_response = eap_payload_response
                                        return REPEAT_STATE, "SYNC FAILURE"

                                    else:
                                        self.current_counter = None
                                        print("RAND", toHex(RAND))
                                        print("AUTN", toHex(AUTN))
                                        print("MAC", toHex(MAC))

                                        res, ck, ik = https_res_ck_ik(self.com_port, toHex(RAND), toHex(AUTN))

                                        if res is not None and ck is None and ik is None:
                                            # RES is AUTS
                                            auts, res = res, None
                                            print("AUTS", auts)
                                            eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex("0018170400000404") + fromHex(auts)
                                            self.eap_payload_response = eap_payload_response
                                            return REPEAT_STATE, "SYNC FAILURE"

                                        else:

                                            print("RES", res)
                                            print("CK", ck)
                                            print("IK", ik)

                                            self.RES, CK, IK = fromHex(res), fromHex(ck), fromHex(ik)
                                            idi = self.identification_initiator[1]
                                            self.KENCR, self.KAUT, self.MSK, self.EMSK, self.MK = ipsec.eap.eap_keys_calculation(idi, CK, IK)
                                            print("KENCR", toHex(self.KENCR))
                                            print("KAUT", toHex(self.KAUT))
                                            print("MSK", toHex(self.MSK))
                                            print("EMSK", toHex(self.EMSK))

                                            # Calculate dynamic EAP payload with proper padding
                                            eap_payload_response = ipsec.eap.build_eap_aka_response(self.eap_identifier, self.RES)

                                            h = hmac.HMAC(self.KAUT, hashes.SHA1())
                                            h.update(eap_payload_response)
                                            hash = h.finalize()[0:16]
                                            self.eap_payload_response = eap_payload_response[:-16] + hash

                                if VECTOR is not None and ENCR_DATA is not None:
                                    print("IV", toHex(VECTOR))
                                    print("ENCR_DATA", toHex(ENCR_DATA))

                                    cipher = Cipher(algorithms.AES(self.KENCR), modes.CBC(VECTOR))
                                    decryptor = cipher.decryptor()
                                    uncipher_data = decryptor.update(ENCR_DATA) + decryptor.finalize()
                                    print("DECRYPTED DATA", toHex(uncipher_data))
                                    eap_attributes = self.decode_eap_attributes(uncipher_data)
                                    print(eap_attributes)
                                    NEXT_REAUTH_ID = self.get_eap_aka_attribute_value(eap_attributes, AT_NEXT_REAUTH_ID)
                                    COUNTER = self.get_eap_aka_attribute_value(eap_attributes, AT_COUNTER)
                                    NONCE_S = self.get_eap_aka_attribute_value(eap_attributes, AT_NONCE_S)

                                    if NEXT_REAUTH_ID is not None:
                                        self.next_reauth_id = NEXT_REAUTH_ID.decode("utf-8")
                                        print("NEXT REAUTH ID", self.next_reauth_id)
                                    else:
                                        # should use permanent identity next
                                        self.next_reauth_id = None

                                    if COUNTER is not None and NONCE_S is not None:
                                        ERROR = False
                                        if self.current_counter is None:
                                            self.current_counter = COUNTER
                                        else:
                                            if COUNTER > self.current_counter:
                                                self.current_counter = COUNTER

                                            else:
                                                # error: include AT_COUNTER_TOO_SMALL
                                                ERROR = True

                                        # XKEY' = SHA1(Identity|counter|NONCE_S| MK)
                                        idi = self.identification_initiator[1]
                                        self.MSK, self.EMSK, self.XKEY = ipsec.eap.eap_keys_calculation_fast_reauth(idi, self.MK, COUNTER, NONCE_S)
                                        print("MSK", toHex(self.MSK))
                                        print("EMSK", toHex(self.EMSK))

                                        vector = self.return_random_bytes(16)
                                        at_iv = bytes([AT_IV]) + fromHex("050000") + vector

                                        if ERROR == False:
                                            at_padding = bytes([AT_PADDING]) + fromHex("0300000000000000000000")
                                            at_counter = bytes([AT_COUNTER]) + b"\x01" + struct.pack("!H", COUNTER)
                                            at_counter_too_small = b""
                                        else:
                                            at_padding = bytes([AT_PADDING]) + fromHex("02000000000000")
                                            at_counter = bytes([AT_COUNTER]) + b"\x01" + struct.pack("!H", COUNTER)
                                            at_counter_too_small = bytes([AT_COUNTER_TOO_SMALL]) + b"\x01\x00\x00"

                                        cipher = Cipher(algorithms.AES(self.KENCR), modes.CBC(vector))
                                        encryptor = cipher.encryptor()
                                        cipher_data = encryptor.update(at_counter + at_counter_too_small + at_padding) + encryptor.finalize()

                                        at_encr_data = bytes([AT_ENCR_DATA]) + fromHex("050000") + cipher_data
                                        length = struct.pack("!H", len(at_iv) + len(at_encr_data) + 28)

                                        eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + length + fromHex("170d0000") + at_iv + at_encr_data + fromHex("0b050000" + 16 * "00")

                                        h = hmac.HMAC(self.KAUT, hashes.SHA1())
                                        h.update(eap_payload_response + NONCE_S)
                                        hash = h.finalize()[0:16]
                                        self.eap_payload_response = eap_payload_response[:-16] + hash

                            else:
                                return OTHER_ERROR, "NO RAND/AUTN IN EAP"

                        elif i[1][3] in (AKA_Identity,):

                            if i[1][4][0][0] in (AT_ANY_ID_REQ, AT_IDENTITY):
                                self.eap_identifier = i[1][1]
                                identity = "0" + self.imsi + "@nai.epc.mnc" + self.mnc + ".mcc" + self.mcc + ".3gppnetwork.org"
                                self.eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex("004417050000") + ipsec.eap.encode_eap_at_identity(identity)

                                # update the EAP length
                                eap = bytearray(self.eap_payload_response)
                                eap_length = struct.pack(">H", len(eap))
                                eap[2] = eap_length[0]
                                eap[3] = eap_length[1]
                                self.eap_payload_response = bytes(eap)

                                return REPEAT_STATE, "EAP IDENTITY REQUESTED"

            if eap_received == True:
                return OK, ""
            else:
                return MANDATORY_INFORMATION_MISSING, "NO EAP PAYLOAD RECEIVED"

    def state_3(self):
        self.message_id_request += 1
        packet = self.create_IKE_AUTH_2()
        self.send_data(packet)
        print("sending IKE_SA_AUTH (2)")

        try:
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True:
                        break
                else:
                    packet, address = self.socket_nat.recvfrom(2000)
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True:
                        break

        except:  # timeout
            return TIMEOUT, "TIMEOUT"

        eap_received = False
        if self.ike_decoded_header["exchange_type"] == IKE_AUTH and self.decoded_payload[0][0] == SK:
            print("received IKE_AUTH (2)")
            for i in self.decoded_payload[0][1]:

                if i[0] == N:  # protocol_id, notify_message_type, spi, notification_data
                    if i[1][1] < 16384:  # error
                        return OTHER_ERROR, str(i[1][1])

                elif i[0] == EAP:
                    eap_received = True
                    if i[1][0] in (EAP_SUCCESS,):

                        hash = self.prf_function.get(self.negotiated_prf)
                        h = hmac.HMAC(self.SK_PI, hash)
                        h.update(bytes([self.identification_initiator[0]]) + b"\x00" * 3 + self.identification_initiator[1].encode("utf-8"))
                        hash_result = h.finalize()
                        self.AUTH_SA_INIT_packet += self.nounce_received + hash_result

                        keypad = b"Key Pad for IKEv2"
                        h = hmac.HMAC(self.MSK, hash)
                        h.update(keypad)
                        hash_result = h.finalize()
                        h = hmac.HMAC(hash_result, hash)
                        h.update(self.AUTH_SA_INIT_packet)
                        self.AUTH_payload = h.finalize()

                    elif i[1][0] in (EAP_REQUEST,) and i[1][2] in (EAP_AKA,):
                        if i[1][3] in (AKA_Challenge,):

                            RAND = self.get_eap_aka_attribute_value(i[1][4], AT_RAND)
                            AUTN = self.get_eap_aka_attribute_value(i[1][4], AT_AUTN)
                            MAC = self.get_eap_aka_attribute_value(i[1][4], AT_MAC)

                            VECTOR = self.get_eap_aka_attribute_value(i[1][4], AT_IV)
                            ENCR_DATA = self.get_eap_aka_attribute_value(i[1][4], AT_ENCR_DATA)

                            self.eap_identifier = i[1][1]

                            if (RAND is not None and AUTN is not None) or (VECTOR is not None and ENCR_DATA is not None):
                                if RAND is not None and AUTN is not None:
                                    self.current_counter = None
                                    print("RAND", toHex(RAND))
                                    print("AUTN", toHex(AUTN))
                                    print("MAC", toHex(MAC))

                                    res, ck, ik = https_res_ck_ik(self.com_port, toHex(RAND), toHex(AUTN))
                                    print("RES", res)
                                    print("CK", ck)
                                    print("IK", ik)

                                    self.RES, CK, IK = fromHex(res), fromHex(ck), fromHex(ik)
                                    idi = self.identification_initiator[1]
                                    self.KENCR, self.KAUT, self.MSK, self.EMSK, self.MK = ipsec.eap.eap_keys_calculation(idi, CK, IK)
                                    print("KENCR", toHex(self.KENCR))
                                    print("KAUT", toHex(self.KAUT))
                                    print("MSK", toHex(self.MSK))
                                    print("EMSK", toHex(self.EMSK))

                                    # Calculate dynamic EAP payload with proper padding
                                    eap_payload_response = ipsec.eap.build_eap_aka_response(self.eap_identifier, self.RES)

                                    h = hmac.HMAC(self.KAUT, hashes.SHA1())
                                    h.update(eap_payload_response)
                                    hash = h.finalize()[0:16]
                                    self.eap_payload_response = eap_payload_response[:-16] + hash

                                if VECTOR is not None and ENCR_DATA is not None:
                                    print("IV", toHex(VECTOR))
                                    print("ENCR_DATA", toHex(ENCR_DATA))

                                    cipher = Cipher(algorithms.AES(self.KENCR), modes.CBC(VECTOR))
                                    decryptor = cipher.decryptor()
                                    uncipher_data = decryptor.update(ENCR_DATA) + decryptor.finalize()
                                    print("DECRYPTED DATA", toHex(uncipher_data))
                                    eap_attributes = self.decode_eap_attributes(uncipher_data)
                                    print(eap_attributes)
                                    NEXT_REAUTH_ID = self.get_eap_aka_attribute_value(eap_attributes, AT_NEXT_REAUTH_ID)

                                    if NEXT_REAUTH_ID is not None:
                                        self.next_reauth_id = NEXT_REAUTH_ID.decode("utf-8")
                                        print("NEXT REAUTH ID", self.next_reauth_id)
                                    else:
                                        # should use permanent identity next
                                        self.next_reauth_id = None

                                return REPEAT_STATE, "NEW AKA_Challenge"

                        elif i[1][3] in (AKA_Notification,):
                            self.eap_identifier = i[1][1]

                            NOTIFICATION = self.get_eap_aka_attribute_value(i[1][4], AT_NOTIFICATION)

                            if NOTIFICATION < 32768:  # error
                                print("EAP AT_NOTIFICATION with ERROR " + str(NOTIFICATION))
                                self.eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex("0008170c0000")
                                return REPEAT_STATE, "General_Failure"

                    elif i[1][0] in (EAP_FAILURE,):
                        return OTHER_ERROR, "EAP FAILURE"

                    else:
                        # check error
                        return MANDATORY_INFORMATION_MISSING, "NO RAND/AUTN IN EAP"

            if eap_received == True:
                return OK, ""
            else:
                return MANDATORY_INFORMATION_MISSING, "NO EAP PAYLOAD RECEIVED"

    def state_4(self):
        self.message_id_request += 1
        packet = self.create_IKE_AUTH_3()
        self.send_data(packet)
        print("sending IKE_AUTH (3)")

        try:
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True:
                        break
                else:
                    packet, address = self.socket_nat.recvfrom(2000)
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True:
                        break

        except:  # timeout
            return TIMEOUT, "TIMEOUT"

        if self.ike_decoded_header["exchange_type"] == IKE_AUTH and self.decoded_payload[0][0] == SK:
            print("received IKE_AUTH (3)")
            for i in self.decoded_payload[0][1]:

                if i[0] == N:  # protocol_id, notify_message_type, spi, notification_data
                    if i[1][1] < 16384:  # error
                        return OTHER_ERROR, str(i[1][1])

                elif i[0] == CP:

                    if i[1][0] == CFG_REPLY:
                        self.ip_address_list = self.get_cp_attribute_value(i[1][1], INTERNAL_IP4_ADDRESS)
                        self.dns_address_list = self.get_cp_attribute_value(i[1][1], INTERNAL_IP4_DNS)
                        self.pcscf_address_list = self.get_cp_attribute_value(i[1][1], P_CSCF_IP4_ADDRESS)
                        self.ipv6_address_list = self.get_cp_attribute_value(i[1][1], INTERNAL_IP6_ADDRESS)
                        self.dnsv6_address_list = self.get_cp_attribute_value(i[1][1], INTERNAL_IP6_DNS)
                        self.pcscfv6_address_list = self.get_cp_attribute_value(i[1][1], P_CSCF_IP6_ADDRESS)
                        print("IPV4 ADDRESS", self.ip_address_list)
                        print("DNS IPV4 ADDRESS", self.dns_address_list)
                        print("P-CSCF IPV4 ADDRESS", self.pcscf_address_list)
                        print("IPV6 ADDRESS", self.ipv6_address_list)
                        print("DNS IPV6 ADDRESS", self.dnsv6_address_list)
                        print("P-CSCF IPV6 ADDRESS", self.pcscfv6_address_list)
                        if self.ip_address_list == [] and self.ipv6_address_list == []:
                            return OTHER_ERROR, "NO IP ADDRESS (IPV4 or IPV6)"
                    else:
                        # check error
                        return OTHER_ERROR, "NO CP REPLY"

                elif i[0] == SA:
                    proposal = i[1][0]
                    protocol_id = i[1][1]
                    self.spi_resp_child = i[1][2]
                    if protocol_id == ESP:
                        self.set_sa_negotiated_child(proposal)
                        print("IPSEC RESP SPI", toHex(self.spi_resp_child))
                        print("IPSEC INIT SPI", toHex(self.spi_init_child))
                    else:
                        return MANDATORY_INFORMATION_MISSING, "MANDATORY_INFORMATION_MISSING"

            self.generate_keying_material_child()
            return OK, ""

    def state_delete(self, initiator, kill=True):
        if initiator == True:

            # if kill == True: #reauth scenario without delete (comment this line, and uncomment the next one)
            if True:
                self.message_id_request += 1
                packet = self.create_INFORMATIONAL_delete(IKE)
                self.send_data(packet)
                print("sending INFORMATIONAL (delete IKE)")

            self.ike_to_ipsec_encoder.send(bytes([INTER_PROCESS_DELETE_SA]))
            self.ike_to_ipsec_decoder.send(bytes([INTER_PROCESS_DELETE_SA]))
            self.delete_routes()
            if kill == True:
                exit(1)

        else:
            for i in self.decoded_payload[0][1]:
                if i[0] == D:  # delete

                    protocol = i[1][0]
                    num_spi = i[1][1]
                    spi_list = i[1][2]
                    if protocol == IKE:
                        print("received INFORMATIONAL (DELETE IKE)")
                        # delete everything, answer and quit
                        packet = self.answer_INFORMATIONAL_delete()
                        self.send_data(packet)
                        print("answering INFORMATIONAL (DELETE IKE)")
                        if self.old_ike_message_received == False:
                            self.ike_to_ipsec_encoder.send(bytes([INTER_PROCESS_DELETE_SA]))
                            self.ike_to_ipsec_decoder.send(bytes([INTER_PROCESS_DELETE_SA]))
                            self.delete_routes()
                            exit(1)

                    elif protocol == ESP:
                        print("received INFORMATIONAL (DELETE SA CHILD)")
                        packet = self.answer_INFORMATIONAL_delete_CHILD(ESP, self.spi_init_child_old)
                        self.send_data(packet)
                        print("answering INFORMATIONAL (DELETE SA CHILD)")

    def state_epdg_create_sa(self):

        isIKE = False
        isESP = False

        print("\nSTATE ePDG STARTED IKE/IPSEC REKEY:\n----------------------------------")

        print(self.decoded_payload)
        for i in self.decoded_payload[0][1]:
            if i[0] == SA:  #
                proposal = i[1][0]
                protocol_id = i[1][1]
                spi = i[1][2]

                if protocol_id == IKE:
                    isIKE = True

                elif protocol_id == ESP:
                    isESP = True

            elif i[0] == NINR:
                self.nounce_received = i[1][0]

        if isIKE == True:
            print("received CREATE_CHILD_SA (IKE)")
            self.state_ue_create_sa(-1)

        if isESP == True:
            print("received CREATE_CHILD_SA (IPSEC)")
            packet = self.answer_NOTIFY_NO_PROPOSAL_CHOSEN()
            self.send_data(packet)
            print("answering CREATE_CHILD_SA (IPSEC: NO PROPROSAL CHOSEN)")

            self.state_ue_create_sa_child()

    def state_ue_create_sa(self, lowest=0):  # IKEv2 REKEY
        print("\nSTATE UE STARTED IKE REKEY:\n--------------------------")
        self.sa_list_negotiated[0][0][1] = 8
        self.sa_list_create_child_sa = self.sa_list_negotiated

        self.dh_create_private_key_and_public_bytes(self.iana_diffie_hellman.get(self.negotiated_diffie_hellman_group))
        self.dh_group_num = self.negotiated_diffie_hellman_group

        self.message_id_request += 1
        packet = self.create_CREATE_CHILD_SA(lowest)
        # send request
        self.send_data(packet)
        print("sending CREATE_CHILD_SA (IKE)")

    def state_ue_create_sa_child(self, lowest=0):  # IPSEC REKEY
        print("\nSTATE UE STARTED IPSEC REKEY:\n--------------------------")

        self.sa_list_create_child_sa_child = self.sa_list_negotiated_child

        self.message_id_request += 1
        packet = self.create_CREATE_CHILD_SA_CHILD(lowest)
        # send request
        self.send_data(packet)
        print("sending CREATE_CHILD_SA (IPSEC)")

    def state_epdg_create_sa_response(self):
        isIKE = False
        isESP = False

        for i in self.decoded_payload[0][1]:
            if i[0] == SA:  #
                proposal = i[1][0]
                protocol_id = i[1][1]
                spi = i[1][2]

                if protocol_id == IKE:
                    isIKE = True
                elif protocol_id == ESP:
                    isESP = True

            elif i[0] == KE:
                dh_peer_group = i[1][0]
                dh_peer_public_key_bytes = i[1][1]
                self.dh_calculate_shared_key(dh_peer_public_key_bytes)

            elif i[0] == NINR:
                self.nounce_received = i[1][0]

        if isIKE == True:
            print("received CREATE_CHILD_SA response IKE")
            self.message_id_request += 1
            packet = self.create_INFORMATIONAL_delete(IKE)

            self.ike_spi_responder_old = self.ike_spi_responder
            self.ike_spi_initiator_old = self.ike_spi_initiator

            self.ike_spi_responder = spi
            self.ike_spi_initiator = self.sa_spi_list[0]  # only one proposal was made

            print("NEW IKE SPI INITIATOR", toHex(self.ike_spi_initiator))
            print("NEW IKE SPI RESPONDER", toHex(self.ike_spi_responder))

            self.generate_new_ike_keying_material()
            self.message_id_request = -1

            # send request
            self.send_data(packet)
            print("sending INFORMATIONAL (DELETE IKE old)")

        if isESP == True:
            print("received CREATE_CHILD_SA response IPSEC")
            self.message_id_request += 1
            self.spi_init_child_old = self.spi_init_child
            self.spi_resp_child_old = self.spi_resp_child
            packet = self.create_INFORMATIONAL_delete(ESP, self.spi_init_child_old)

            self.spi_init_child = self.sa_spi_list[0]  # only one proposal was made
            self.spi_resp_child = spi

            print("NEW CHILD SPI INITIATOR ", toHex(self.spi_init_child))
            print("NEW CHILD SPI RESPONDER", toHex(self.spi_resp_child))

            self.generate_keying_material_child()
            inter_process_list_start_encoder = [
                INTER_PROCESS_UPDATE_SA,
                [
                    (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                    (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_EI),
                    (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                    (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AI),
                    (INTER_PROCESS_IE_SPI_RESP, self.spi_resp_child),
                ],
            ]

            inter_process_list_start_decoder = [
                INTER_PROCESS_UPDATE_SA,
                [
                    (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                    (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_ER),
                    (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                    (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AR),
                    (INTER_PROCESS_IE_SPI_INIT, self.spi_init_child),
                ],
            ]

            self.ike_to_ipsec_encoder.send(self.encode_inter_process_protocol(inter_process_list_start_encoder))
            self.ike_to_ipsec_decoder.send(self.encode_inter_process_protocol(inter_process_list_start_decoder))

            # send request
            self.send_data(packet)
            print("sending INFORMATIONAL (DELETE IPSEC old)")

    def state_connected(self):
        # set udp 4500 socket (self.socket_nat)

        self.set_routes()

        # set ipsec tunnel handlers
        self.ike_to_ipsec_encoder, self.ipsec_encoder_to_ike = multiprocessing.Pipe()
        self.ike_to_ipsec_decoder, self.ipsec_decoder_to_ike = multiprocessing.Pipe()

        ipsec_input_worker = multiprocessing.Process(target=self.encapsulate_ipsec, args=([self.ipsec_encoder_to_ike],))
        ipsec_input_worker.start()
        ipsec_output_worker = multiprocessing.Process(target=self.decapsulate_ipsec, args=([self.ipsec_decoder_to_ike],))
        ipsec_output_worker.start()

        inter_process_list_start_encoder = [
            INTER_PROCESS_CREATE_SA,
            [
                (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_EI),
                (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AI),
                (INTER_PROCESS_IE_SPI_RESP, self.spi_resp_child),
            ],
        ]

        inter_process_list_start_decoder = [
            INTER_PROCESS_CREATE_SA,
            [
                (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_ER),
                (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AR),
                (INTER_PROCESS_IE_SPI_INIT, self.spi_init_child),
            ],
        ]

        self.ike_to_ipsec_encoder.send(self.encode_inter_process_protocol(inter_process_list_start_encoder))
        self.ike_to_ipsec_decoder.send(self.encode_inter_process_protocol(inter_process_list_start_decoder))

        socket_list = [sys.stdin, self.socket, self.ike_to_ipsec_decoder]

        while True:

            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

            for sock in read_sockets:

                if sock == self.socket:

                    packet, server_address = self.socket.recvfrom(2000)
                    if server_address[0] == self.server_address[0]:  # check server IP address. source port could be different than 500 or 4500, if it's a request reponse must be sent to the same port

                        self.decode_ike(packet)
                        if self.ike_decoded_ok == True:

                            if self.ike_decoded_header["exchange_type"] == INFORMATIONAL and self.decoded_payload[0][0] == SK and self.ike_decoded_header["flags"][0] == 0:
                                self.state_delete(False)

                            elif self.ike_decoded_header["exchange_type"] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header["flags"][0] == 0:
                                self.state_epdg_create_sa()

                            elif self.ike_decoded_header["exchange_type"] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header["flags"][0] == 1:
                                self.state_epdg_create_sa_response()

                        if self.old_ike_message_received == True:
                            self.old_ike_message_received = False

                elif sock == self.ike_to_ipsec_decoder:
                    pipe_packet = self.ike_to_ipsec_decoder.recv()
                    decode_list = self.decode_inter_process_protocol(pipe_packet)
                    if decode_list[0] == INTER_PROCESS_IKE:

                        packet = decode_list[1][0][1]

                        # if received via pipe it was sent to port udp 4500 (exclude 4 initial bytes)
                        self.decode_ike(packet[4:])

                        if self.ike_decoded_ok == True:

                            if self.ike_decoded_header["exchange_type"] == INFORMATIONAL and self.decoded_payload[0][0] == SK and self.ike_decoded_header["flags"][0] == 0:
                                self.state_delete(False)

                            elif self.ike_decoded_header["exchange_type"] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header["flags"][0] == 0:
                                self.state_epdg_create_sa()

                            elif self.ike_decoded_header["exchange_type"] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header["flags"][0] == 1:
                                self.state_epdg_create_sa_response()

                        if self.old_ike_message_received == True:
                            self.old_ike_message_received = False

                else:
                    msg = sys.stdin.readline()
                    if msg == "q\n":  # quit
                        self.state_delete(True)
                    elif msg == "i\n":  # rekey ike
                        self.state_ue_create_sa()
                    elif msg == "c\n":  # rekey sa child
                        self.state_ue_create_sa_child()
                    elif msg == "r\n":  # restart process
                        self.state_delete(True, False)
                        if self.next_reauth_id is not None:
                            self.set_identification(IDI, ID_RFC822_ADDR, self.next_reauth_id)
                        else:
                            self.set_identification(IDI, ID_RFC822_ADDR, "0" + self.imsi + "@nai.epc.mnc" + self.mnc + ".mcc" + self.mcc + ".3gppnetwork.org")

                        self.iterations = 2
                        return

                    else:
                        print("\nPress q to quit, i to rekey ike, c to rekey child sa, r to reauth.\n")

    def start_ike(self):
        self.iterations = 2
        self.cookie = False
        while self.iterations > 0:

            self.iterations -= 1

            print("\nSTATE 1:\n-------")
            result, info = self.state_1()
            if result in (REPEAT_STATE, TIMEOUT):
                print(self.errors.get(result), ":", info)
                print("\nSTATE 1 (retry 1):\n------- -------")
                result, info = self.state_1(retry=True)
            elif result in (REPEAT_STATE_COOKIE,):
                print(self.errors.get(result), ":", info)
                print("\nSTATE 1 (retry 1 with cookie):\n------- -------")
                result, info = self.state_1(retry=True, cookie=True)

            if result in (REPEAT_STATE, TIMEOUT):
                print(self.errors.get(result), ":", info)
                print("\nSTATE 1: (retry 2)\n------- -------")
                if self.cookie == True:
                    result, info = self.state_1(retry=True, cookie=True)
                else:
                    result, info = self.state_1(retry=True)

            if result == OK:
                print("\nSTATE 2:\n-------")
                result, info = self.state_2()
            else:
                print(self.errors.get(result), ":", info)
                continue

            if result in (REPEAT_STATE, OK):
                if result in (REPEAT_STATE,):
                    print(self.errors.get(result), ":", info)
                    print("\nSTATE 2 (repeat):\n---------------")
                    result, info = self.state_2(retry=True)
                if result in (OK,):
                    print("\nSTATE 3:\n-------")
                    result, info = self.state_3()
            else:
                print(self.errors.get(result), ":", info)
                continue

            if result in (OK, REPEAT_STATE):
                if result in (REPEAT_STATE,):
                    print(self.errors.get(result), ":", info)
                    print("\nSTATE 3 (repeat):\n---------------")
                    result, info = self.state_3()
                if result in (OK,):
                    print("\nSTATE 4:\n-------")
                    result, info = self.state_4()
            else:
                print(self.errors.get(result), ":", info)
                continue

            if result == OK:
                print("\nSTATE CONNECTED. Press q to quit, i to rekey ike, c to rekey child sa, r to reauth.\n")
                self.state_connected()
            else:
                print(self.errors.get(result), ":", info)
                continue

        exit(1)


def toHex(value):  # bytes hex string
    return hexlify(value).decode("utf-8")


def fromHex(value):  # hex string to bytes
    return unhexlify(value)


def return_imsi(serial_interface_or_reader_index):
    return https_imsi(serial_interface_or_reader_index)


def return_res_ck_ik(serial_interface_or_reader_index, rand, autn, ki, op, opc):
    return https_res_ck_ik(serial_interface_or_reader_index, rand, autn)


# https functions
def https_imsi(server):
    if not server.startswith("http"):
        # Assume HTTPS if no protocol specified
        server = "https://" + server
    r = requests.get(server + "/?type=imsi", verify=False)
    return r.json()["imsi"]


def https_res_ck_ik(server, rand, autn):
    if not server.startswith("http"):
        # Assume HTTPS if no protocol specified
        server = "https://" + server
    r = requests.get(server + "/?type=rand-autn&rand=" + rand + "&autn=" + autn, verify=False)
    return r.json()["res"], r.json()["ck"], r.json()["ik"]
