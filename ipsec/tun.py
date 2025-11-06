import os
import sys
import socket
import fcntl
import subprocess

class Tun:
    def __init__(self):
        pass

    def write_packet(self, packet: bytes):
        raise NotImplementedError

    def read_packet(self, size: int = 65536) -> bytes:
        raise NotImplementedError

    def ifname(self) -> str:
        raise NotImplementedError
    
    def add_address(self, ip: str, ipv6: bool = False):
        raise NotImplementedError

    def close(self):
        pass

class TunLinux(Tun):
    TUN_DEVICE = "/dev/net/tun" # from <linux/if_tun.h>
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    IFF_UP = 0x1
    IFF_RUNNING = 0x40
    TUNSETIFF = 0x400454ca  # _IOW('T', 202, int) - common on Linux
    IFNAMSIZ = 16
    SIOCSIFFLAGS = 0x8914
    SIOCSIFADDR = 0x8916  # from <linux/sockios.h>
    SIOCSIFNETMASK = 0x891c

    def __init__(self):
        super().__init__()
        # open /dev/net/tun
        fd = os.open(self.TUN_DEVICE, os.O_RDWR)
        self.fd = fd

        # we use empty name hint to get tunX automatically
        # ifreq: char ifr_name[IFNAMSIZ]; short ifr_flags; rest unused
        ifreq = b"\x00" * self.IFNAMSIZ + (self.IFF_TUN | self.IFF_NO_PI).to_bytes(2, "little") + b"\x00" * 14
        
        # ioctl to create
        try:
            res = fcntl.ioctl(self.fd, self.TUNSETIFF, ifreq)
        except OSError:
            os.close(self.fd)
            raise
        # the kernel returns the actual interface name in the ifreq
        self._ifname = res[:self.IFNAMSIZ].split(b'\x00', 1)[0].decode()

        # hack: disable automatic IPv6 address generation on the interface
        # (to make behavior similar to macOS utun)
        # equivalent: ip link set dev <ifname> addrgenmode none
        addr_gen_path = f"/proc/sys/net/ipv6/conf/{self._ifname}/addr_gen_mode"
        try:
            with open(addr_gen_path, "w") as f:
                f.write("1\n")
        except Exception:
            pass  # not critical

        # bring up the interface
        # equivalent: ip link set dev <ifname> up
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # ifreq = char name[16]; short flags; 14 padding
        ifname_bytes = self._ifname.encode("utf-8").ljust(self.IFNAMSIZ, b"\x00")
        flags_bytes = (self.IFF_UP | self.IFF_RUNNING).to_bytes(2, "little")
        ifreq = ifname_bytes + flags_bytes + b"\x00" * 14
        fcntl.ioctl(s, self.SIOCSIFFLAGS, ifreq)

        print(f"Initialized Linux TUN: {self._ifname} (fd={self.fd})")

    def write_packet(self, packet: bytes):
        # Linux tun device expects pure IP packet (no extra header if IFF_NO_PI)
        os.write(self.fd, packet)
        # optional: return number of bytes written
        return

    def read_packet(self, size: int = 65536) -> bytes:
        return os.read(self.fd, size)

    def ifname(self) -> str:
        return self._ifname
    
    def _add_address_netlink(self, ifname: str, addr: str, prefixlen: int):
        RTM_NEWADDR = 20
        NLM_F_REQUEST = 1
        NLM_F_ACK = 4
        NLM_F_CREATE = 0x400
        NLM_F_EXCL = 0x200
        AF_INET6 = socket.AF_INET6
        NETLINK_ROUTE = 0
        AF_NETLINK = 16

        IFA_ADDRESS = 1
        IFA_LOCAL = 2

        s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        pid = os.getpid()
        ifindex = socket.if_nametoindex(ifname)

        ip_bytes = socket.inet_pton(AF_INET6, addr)

        def nlattr(attr_type, payload):
            length = len(payload) + 4
            pad = (4 - (length % 4)) % 4
            return (
                length.to_bytes(2, "little") +
                attr_type.to_bytes(2, "little") +
                payload +
                b"\x00" * pad
            )

        ifa_family = AF_INET6
        ifa_prefixlen = prefixlen
        ifa_flags = 0
        ifa_scope = 0
        ifa_index = ifindex

        ifa_hdr = (
            ifa_family.to_bytes(1, "little") +
            ifa_prefixlen.to_bytes(1, "little") +
            ifa_flags.to_bytes(1, "little") +
            ifa_scope.to_bytes(1, "little") +
            ifa_index.to_bytes(4, "little")
        )

        attrs = nlattr(IFA_ADDRESS, ip_bytes) + nlattr(IFA_LOCAL, ip_bytes)
        payload = ifa_hdr + attrs

        # ---- Netlink header ----
        nlmsg_len = 16 + len(payload)
        nlmsg_type = RTM_NEWADDR
        nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
        nlmsg_seq = 1
        nlmsg_pid = pid

        nlhdr = (
            nlmsg_len.to_bytes(4, "little") +
            nlmsg_type.to_bytes(2, "little") +
            nlmsg_flags.to_bytes(2, "little") +
            nlmsg_seq.to_bytes(4, "little") +
            nlmsg_pid.to_bytes(4, "little")
        )

        msg = nlhdr + payload
        s.send(msg)

        try:
            resp = s.recv(8192)
            offset = 0
            while offset < len(resp):
                # Netlink header: 16 bytes
                if len(resp) - offset < 16:
                    print("Incomplete netlink header")
                    break

                nlmsg_len = int.from_bytes(resp[offset:offset+4], "little")
                nlmsg_type = int.from_bytes(resp[offset+4:offset+6], "little")
                nlmsg_flags = int.from_bytes(resp[offset+6:offset+8], "little")
                nlmsg_seq = int.from_bytes(resp[offset+8:offset+12], "little")
                nlmsg_pid = int.from_bytes(resp[offset+12:offset+16], "little")

                payload = resp[offset+16:offset+nlmsg_len]

                # Check for ACK or error
                if nlmsg_type == 2:  # NLMSG_ERROR
                    if len(payload) >= 4:
                        error_code = int.from_bytes(payload[:4], "little", signed=True)
                        if error_code == 0:
                            print("ACK received")
                        else:
                            print(f"Netlink error: {error_code}")
                    else:
                        print("Malformed NLMSG_ERROR")
                else:
                    print(f"Message type {nlmsg_type}, length {nlmsg_len}")

                # Move to next message
                offset += nlmsg_len
                if nlmsg_len % 4 != 0:
                    offset += 4 - (nlmsg_len % 4)  # 4-byte alignment
        except socket.error as e:
            print("Socket error:", e)
        finally:
            s.close()
    
    def add_address(self, ip: str, ipv6: bool = False):
        if '/' in ip:
            addr, prefixlen_str = ip.split('/', 1)
            prefixlen = int(prefixlen_str)
        else:
            addr = ip
            prefixlen = 64
        if ipv6:
            self._add_address_netlink(self._ifname, addr, prefixlen)
        else:
            if prefixlen == 64:
                prefixlen = 32

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = self._ifname.encode('utf-8').ljust(16, b'\x00')[:16] + socket.AF_INET.to_bytes(2, 'little') + b'\x00'*2 + socket.inet_aton(addr) + b'\x00'*8
            mask = (0xffffffff << (32 - prefixlen)) & 0xffffffff
            ifreq_mask = self._ifname.encode('utf-8').ljust(16, b'\x00')[:16] + socket.AF_INET.to_bytes(2, 'little') + b'\x00'*2+ mask.to_bytes(4, 'big') + b'\x00'*8
            fcntl.ioctl(s, self.SIOCSIFADDR, ifreq)
            fcntl.ioctl(s, self.SIOCSIFNETMASK, ifreq_mask)

    def close(self):
        try:
            os.close(self.fd)
        except Exception:
            pass

class TunMacOS(Tun):
    CTLIOCGINFO = 0xC0644E03  # ioctl to get control id
    SIOCSIFADDR = 0x8020690
    UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
    CTL_INFO_NAME_SIZE = 96
    AF_SYSTEM = 32
    SYSPROTO_CONTROL = 2


    def __init__(self):
        super().__init__()
        # AF_SYSTEM / SYSPROTO_CONTROL socket
        s = socket.socket(self.AF_SYSTEM, socket.SOCK_DGRAM, self.SYSPROTO_CONTROL)

        # build ctl_info as bytearray: 4 bytes ctl_id, 96 bytes name
        ctl_info = bytearray(4 + self.CTL_INFO_NAME_SIZE)
        ctl_info[4:4+len(self.UTUN_CONTROL_NAME)] = self.UTUN_CONTROL_NAME

        # ioctl fills in ctl_id
        fcntl.ioctl(s, self.CTLIOCGINFO, ctl_info, True)
        ctl_id = int.from_bytes(ctl_info[:4], "little")

        # connect using Python's (ctl_id, unit) tuple form; unit=0 => kernel assigns
        s.connect((ctl_id, 0))

        self.sock = s

        UTUN_OPT_IFNAME = 2
        ifname = s.getsockopt(self.SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 32)
        self._ifname = ifname.split(b'\x00', 1)[0].decode()

        print(f"Initialized macOS utun: {self._ifname} (fd={s.fileno()})")

    def add_address(self, ip: str, ipv6: bool = False):
        # Hack: just use ifconfig
        if ipv6:
            subprocess.run(["ifconfig", self._ifname, "inet6", ip, "alias"])
        else:
            subprocess.run(["ifconfig", self._ifname, "inet", ip, "alias"])

    def write_packet(self, packet: bytes):
        # utun expects a 4-byte network-order family header before the packet bytes.
        # For IPv4: socket.AF_INET (2); IPv6: socket.AF_INET6 (10). We'll assume IPv6 if packet starts with 0x6.
        fam = socket.AF_INET6 if packet and (packet[0] >> 4) == 6 else socket.AF_INET
        hdr = fam.to_bytes(4, "big")
        self.sock.sendall(hdr + packet)

    def read_packet(self, size: int = 65536) -> bytes:
        # recv includes 4-byte family header
        data = self.sock.recv(size + 4)
        if len(data) < 4:
            return b''
        return data[4:]

    def ifname(self) -> str:
        return self._ifname

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

def open_tun() -> Tun:
    """
    Open a platform-appropriate TUN/UTUN and return a Tun-derived object.
    """
    if sys.platform.startswith("linux"):
        return TunLinux()
    elif sys.platform == "darwin":
        return TunMacOS()
    else:
        raise NotImplementedError(f"TUN not implemented on platform {sys.platform}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: creating tun/utun typically requires root privileges.", file=sys.stderr)

    t = open_tun()
    print("ifname:", t.ifname())

    # Example: write an IPv6 packet (UNCIPHER PACKET example)
    example_hex = "6000000000383afffe80000000000000000000000829db40ff02000000000000000000000000000186004fe4ff00070800000000000003e803044040ffffffffffffffff0000000026000382ac851ae600000000000000000501000000000596"
    pkt = bytes.fromhex(example_hex)

    t.add_address("fe80::362c:527b:45bd:999d/64", ipv6=True)
    t.add_address("10.0.0.1/22", ipv6=False)
    input("Press Enter to write example packet...")
    t.write_packet(pkt)

    # try to read (non-blocking would be nicer in real apps)
    try:
        data = t.read_packet()
        if data:
            print("Read packet:", data.hex())
        else:
            print("No packet returned on read()")
    except Exception as e:
        print("Read attempt failed/timeout:", e)

    t.close()
