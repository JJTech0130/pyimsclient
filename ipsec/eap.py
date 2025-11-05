import struct 
from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify

def encode_eap_at_identity(identity):
    """ Returns the EAP AT Identity as bytes """
    # 4 bytes -> header (type, at_len, identity_len)
    full_len = 4 + len(identity)
    at_len = int(full_len / 4)
    pad = 0
    if full_len % 4:
        pad = 4 - (full_len % 4)
        at_len += 1
    # 0e -> AT_IDENTITY
    eap_at_identity = (bytes([0x0e, at_len])
            + struct.pack('>H', len(identity))
            + identity.encode("utf-8")
            + pad * b'\x00')
    return eap_at_identity

def eap_keys_calculation(idi, ck, ik):
    identity = idi.encode('utf-8')  # idi value
    digest = hashes.Hash(hashes.SHA1())
    digest.update(identity + ik + ck)
    MK = digest.finalize()
    print('MK',hexlify(MK).decode('utf-8'))
    
    result = b''
    xval = MK
    modulus = pow(2,160)
    
    for i in range(4):
        w0 = sha1_dss(xval)
        xval = ((int.from_bytes(xval,'big') + int.from_bytes(w0, 'big') + 1 ) % modulus).to_bytes(20,'big')
        w1 = sha1_dss(xval)
        xval = ((int.from_bytes(xval,'big') + int.from_bytes(w1, 'big') + 1 ) % modulus).to_bytes(20,'big')
        
        result += w0 + w1

    # return     
    return result[0:16],result[16:32],result[32:96],result[96:160],MK
    
# idi = self.identification_initiator[1]
# MK = self.MK
def eap_keys_calculation_fast_reauth(idi, MK, counter, nonce_s):
    identity = idi.encode('utf-8') #idi value
    digest = hashes.Hash(hashes.SHA1())
    digest.update(identity + struct.pack('!H',counter) + nonce_s + MK)
    XKEY = digest.finalize()
    print('XKEY',hexlify(XKEY).decode('utf-8'))
    
    result = b''
    xval = XKEY
    modulus = pow(2,160)
    
    for i in range(4):
        w0 = sha1_dss(xval)
        xval = ((int.from_bytes(xval,'big') + int.from_bytes(w0, 'big') + 1 ) % modulus).to_bytes(20,'big')
        w1 = sha1_dss(xval)
        xval = ((int.from_bytes(xval,'big') + int.from_bytes(w1, 'big') + 1 ) % modulus).to_bytes(20,'big')
        
        result += w0 + w1

    # return     
    return result[0:64],result[64:128],XKEY        
    
def build_eap_aka_response(eap_identifier, res):
    """
    Build EAP-AKA Response payload with proper length calculation and padding.
    
    Args:
        eap_identifier: EAP packet identifier
        res: RES value (4-16 bytes according to 3GPP standard)
        
    Returns:
        Complete EAP-AKA response payload with proper length and padding
    """
    # Validate RES length (must be 4-16 bytes according to 3GPP TS 33.102)
    res_len = len(res)
    if res_len < 4 or res_len > 16:
        raise ValueError(f"RES length must be between 4-16 bytes, got {res_len}")
    
    # EAP-AKA fixed parts
    eap_code = bytes([2])  # Response
    eap_id = bytes([eap_identifier])
    eap_aka_header = unhexlify('1701000003030040')  # EAP-AKA Challenge Response header
    eap_aka_header = unhexlify('1701000003')  # EAP-AKA Challenge Response header
    eap_res_bit_len = struct.pack('!H', res_len * 8)
    at_mac_header = unhexlify('0b050000')  # AT_MAC attribute header (16 bytes follow)
    
    # Calculate payload length before MAC
    # Structure: Code(1) + ID(1) + Length(2) + EAP-AKA Header(8) + RES(var) + AT_MAC(20)
    base_length = 1 + 1 + 2 + len(eap_aka_header) + 3 + res_len + len(at_mac_header) + 16
    
    # EAP-AKA payloads must be multiples of 4 bytes - add padding if needed
    padding_needed = (4 - (base_length % 4)) % 4
    eap_res_4bytes_len = struct.pack('!B', (res_len + padding_needed) // 4 + 1)
    padding = bytes(padding_needed)
    
    # Final length including padding
    total_length = base_length + padding_needed
    
    # Build length field (2 bytes, big endian)
    length_bytes = struct.pack('!H', total_length)
    
    # Construct payload without MAC (MAC placeholder is 16 zero bytes)
    eap_payload_response = (eap_code + 
                            eap_id + 
                            length_bytes + 
                            eap_aka_header + 
                            eap_res_4bytes_len + 
                            eap_res_bit_len + 
                            res + 
                            padding +  # Add padding after RES if needed
                            at_mac_header + 
                            bytes(16))  # MAC placeholder
    
    return eap_payload_response


def sha1_dss(data):  #for MSK
#based on code from https://codereview.stackexchange.com/questions/37648/python-implementation-of-sha1    

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    #special padding. data always 160 bits (20 bytes, so 44 bytes left to 64Bytes block)
    padding = 44*b'\x00'
    padded_data = data + padding 
    
    thunks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
    for thunk in thunks:
        w = list(struct.unpack('>16L', thunk)) + [0] * 64
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(0, 80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            else:
                raise ValueError("Invalid loop index")

            a, b, c, d, e = rol(a, 5) + f + e + k + w[i] & 0xffffffff, \
                            a, rol(b, 30), c, d

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    #return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
    return struct.pack('!I',h0) + struct.pack('!I',h1) + struct.pack('!I',h2) + struct.pack('!I',h3) + struct.pack('!I',h4)

