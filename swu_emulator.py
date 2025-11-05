from optparse import OptionParser
import socket
from ipsec import *
from ipsec.swu import swu

#################################################################################################################    
#####
#####   SA Structure:
#####   ------------
#####
#####   sa_list = [ (proposal 1), (proposal 2), ... , (proposal n)   ]
#####
#####   proposal = (Protocol ID, SPI Size) , (Transform 1), (transform 2), ... , (transform n)
#####
#####   transform = Tranform Type, Transform ID, (Transform Attributes)
#####
#####   transform attribute = Attribute type, value
#####
#################################################################################################################


#################################################################################################################    
#####
#####   TS Structure:
#####   ------------
#####
#####   ts_list = [ (ts 1), (ts 2), ... , (ts n)   ]
#####
#####   ts = ts_type, ip_protocol_id, start_port, end_port, starting_address, ending_address
#####
#################################################################################################################


#################################################################################################################    
#####
#####   CP Structure:
#####   ------------
#####
#####   cp_list = [ cfg_type, (attribute 1), ... , (attribute n)   ]
#####
#####   attribute = attribute type, value1, value2, .... (depends on the attribute type)
#####
#################################################################################################################



def main():

    cp_list = [
        CFG_REQUEST, 
        [INTERNAL_IP4_ADDRESS],
        [INTERNAL_IP4_DNS],
        [INTERNAL_IP6_ADDRESS],
        [INTERNAL_IP6_DNS],
        [P_CSCF_IP4_ADDRESS],
        [P_CSCF_IP6_ADDRESS]
    ]

    ts_list_initiator = [
        [TS_IPV4_ADDR_RANGE,ANY,0,65535,'0.0.0.0','255.255.255.255'],
        [TS_IPV6_ADDR_RANGE,ANY,0,65535,'::','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
    ]

    ts_list_responder = [
        [TS_IPV4_ADDR_RANGE,ANY,0,65535,'0.0.0.0','255.255.255.255'],
        [TS_IPV6_ADDR_RANGE,ANY,0,65535,'::','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']        
    ]


    sa_list = [
    [
       [IKE,0],
       [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
       [PRF,PRF_HMAC_SHA2_256],
       [INTEG,AUTH_HMAC_SHA2_256_128],
       [D_H,MODP_2048_bit] 
    ],
    # [
    #    [IKE,0],
    #    [ENCR,ENCR_NULL],
    #    [PRF,PRF_HMAC_SHA1],
    #    [INTEG,AUTH_HMAC_SHA1_96],
    #    [D_H,MODP_1024_bit] 
    # ]    ,
    # [
    #    [IKE,0],
    #    [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
    #    [PRF,PRF_HMAC_SHA1],
    #    [INTEG,AUTH_HMAC_SHA1_96],
    #    [D_H,MODP_2048_bit] 
    # ]    ,
    
    # [
    #    [IKE,0],
    #    [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
    #    [PRF,PRF_HMAC_SHA1],
    #    [INTEG,AUTH_HMAC_SHA1_96],
    #    [D_H,MODP_1024_bit]  
    # ]
  
    ]


    sa_list_child = [
    # [
    #     [ESP,4],
    #     [ENCR,ENCR_AES_GCM_8,[KEY_LENGTH,256]],
    #     [INTEG,NONE],
    #     [ESN,ESN_NO_ESN]
    # ],
    # [
    #     [ESP,4],
    #     [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
    #     [INTEG,AUTH_HMAC_SHA2_256_128],
    #     [ESN,ESN_NO_ESN]
    # ] ,
    # [
    #     [ESP,4],
    #     [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
    #     [INTEG,AUTH_HMAC_SHA2_384_192],
    #     [ESN,ESN_NO_ESN]
    # ] ,
    # [
    #     [ESP,4],
    #     [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
    #     [INTEG,AUTH_HMAC_SHA2_512_256],
    #     [ESN,ESN_NO_ESN]
    # ]     ,
    # [
    #     [ESP,4],
    #     [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
    #     [INTEG,AUTH_HMAC_MD5_96],
    #     [ESN,ESN_NO_ESN]
    # ]    ,
    # [
    #     [ESP,4],
    #     [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
    #     [INTEG,AUTH_HMAC_SHA1_96],
    #     [ESN,ESN_NO_ESN]
    # ] ,
    [
        [ESP,4],
        [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
        [INTEG,AUTH_HMAC_SHA1_96],
        [ESN,ESN_NO_ESN]
    ]     
    ]


    parser = OptionParser()    
    parser.add_option("-m", "--modem", dest="modem", default=DEFAULT_COM, help="modem port (i.e. COMX, or /dev/ttyUSBX), smartcard reader index (0, 1, 2, ...), or server for https")
    parser.add_option("-s", "--source", dest="source_addr",default="0.0.0.0",help="IP address of source interface used for IKE/IPSEC")
    parser.add_option("-d", "--dest", dest="destination_addr",default=DEFAULT_SERVER,help="ip address or fqdn of ePDG") 
    parser.add_option("-a", "--apn", dest="apn", default=DEFAULT_APN, help="APN to use")    
    parser.add_option("-g", "--gateway_ip_address", dest="gateway_ip_address", help="gateway IP address")    
    parser.add_option("-I", "--imsi", dest="imsi",default=DEFAULT_IMSI,help="IMSI") 
    parser.add_option("-M", "--mcc", dest="mcc",default=DEFAULT_MCC,help="MCC of ePDG (3 digits)") 
    parser.add_option("-N", "--mnc", dest="mnc",default=DEFAULT_MNC,help="MNC of ePDG (3 digits)")   

    parser.add_option("-K", "--ki", dest="ki", help="ki for Milenage (if not using option -m)")    
    parser.add_option("-P", "--op", dest="op", help="op for Milenage (if not using option -m)")    
    parser.add_option("-C", "--opc", dest="opc", help="opc for Milenage (if not using option -m)") 
    parser.add_option("-n", "--netns", dest="netns", help="Name of network namespace for tun device")  
    parser.add_option("-S", "--sqn", dest="sqn", help="SQN (6 hex bytes)")        
    
    (options, args) = parser.parse_args()
    
    try:
        destination_addr = socket.gethostbyname(options.destination_addr)
    except:
        print('Unable to resolve ' + options.destination_addr + '. Exiting.')
        exit(1)

    a = swu(options.source_addr,destination_addr,options.apn,options.modem,options.gateway_ip_address,options.mcc,options.mnc,options.imsi,options.ki,options.op,options.opc,options.netns, options.sqn)

    if options.imsi == DEFAULT_IMSI: a.get_identity()
    a.set_sa_list(sa_list)
    a.set_sa_list_child(sa_list_child)
    a.set_ts_list(TSI, ts_list_initiator)
    a.set_ts_list(TSR, ts_list_responder)
    a.set_cp_list(cp_list)
    a.start_ike()
    
    
    
if __name__ == "__main__":
    main()
    