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
    
    def add_address(self, addr: str, ipv6: bool = False):
        raise NotImplementedError

    def close(self):
        pass

    def fileno(self) -> int:
        # Return the file descriptor number for use with select()
        # This should probably be removed at some point
        raise NotImplementedError

class TunLinux(Tun):
    TUNSETIFF = 0x400454ca  # _IOW('T', 202, int) from <linux/if_tun.h>
    IFF_TUN = 0x0001        #                     from <linux/if_tun.h>
    IFF_NO_PI = 0x1000      #                     from <linux/if_tun.h>
    IFNAMSIZ = 16           #                     from <linux/if.h>

    def __init__(self):
        super().__init__()

        # interfaces created with /dev/net/tun are automatically removed when the program exits
        self._fd = os.open("/dev/net/tun", os.O_RDWR)

        # we use empty ifr_name hint to get tunX automatically
        # from <linux/if.h>
        # struct ifreq: char ifr_name[IFNAMSIZ]; short ifr_flags; rest unused
        ifreq = bytearray(b"\x00" * self.IFNAMSIZ + (self.IFF_TUN | self.IFF_NO_PI).to_bytes(2, "little") + b"\x00" * 14)
        
        fcntl.ioctl(self._fd, self.TUNSETIFF, ifreq)
        self._ifname = ifreq[:self.IFNAMSIZ].split(b'\x00', 1)[0].decode()

        # hack: disable SLAAC/accepting RAs over the tunnel
        open(f"/proc/sys/net/ipv6/conf/{self._ifname}/accept_ra", "w").write("0\n")

        # bring up the interface
        subprocess.run(["/sbin/ip", "link", "set", "dev", self._ifname, "up"])

        print(f"Initialized Linux TUN: {self._ifname} (fd={self._fd})")

    def write_packet(self, packet: bytes):
        os.write(self._fd, packet)

    def read_packet(self, size: int = 65536) -> bytes:
        return os.read(self._fd, size)

    def ifname(self) -> str:
        return self._ifname
    
    def add_address(self, addr: str, ipv6: bool = False):
        # Hack: shell out to ip, replace this with netlink in the future?
        if ipv6:
            subprocess.run(["/sbin/ip", "-6", "addr", "add", addr, "dev", self._ifname])
            # Hack: IPv6 won't work on the tunnel interface without a default route, use a high metric to avoid interfering with normal routing
            # (add utun suffix to avoid conflicts if multiple tunnels are used)
            subprocess.run(["/sbin/ip", "-6", "route", "add", "default", "dev", self._ifname, "metric", "2000" + self._ifname[4:]])
        else:
            subprocess.run(["/sbin/ip", "-4", "addr", "add", addr, "dev", self._ifname])

    def close(self):
        os.close(self._fd)

    def fileno(self) -> int:
        return self._fd

class TunMacOS(Tun):
    CTLIOCGINFO = 0xC0644E03 # _IOWR('N', 3, struct ctl_info) from <sys/kern_control.h>
    SIOCSIFADDR = 0x8020690  # _IOW('i', 12, struct ifreq)    from <sys/sockio.h>
    SYSPROTO_CONTROL = 2     #                                from <sys/sys_domain.h>
    UTUN_OPT_IFNAME = 2      #                                from <net/if_utun.h>
    AF_SYSTEM = 32           #                                from <sys/socket.h>


    def __init__(self):
        super().__init__()
        
        self._sock = socket.socket(self.AF_SYSTEM, socket.SOCK_DGRAM, self.SYSPROTO_CONTROL)

        # from <sys/kern_control.h>
        # struct ctl_info { 
        #     u_int32_t ctl_id; /* Kernel Controller ID */
        #     char ctl_name[96  ]; /* Kernel Controller Name (a C string) */
        # };
        ctl_info = bytearray(b"\x00" * 4 + b"com.apple.net.utun_control".ljust(96, b"\x00"))

        # get the Controller ID for utun_control
        fcntl.ioctl(self._sock, self.CTLIOCGINFO, ctl_info, True)
        ctl_id = int.from_bytes(ctl_info[:4], "little")

        # connecting to the control creates a new utun interface
        # 0 means the kernel chooses the next available utunX
        self._sock.connect((ctl_id, 0))

        # get the assigned interface name
        ifname = self._sock.getsockopt(self.SYSPROTO_CONTROL, self.UTUN_OPT_IFNAME, 32)
        self._ifname = ifname.split(b'\x00', 1)[0].decode()

        print(f"Initialized macOS utun: {self._ifname} (fd={self._sock.fileno()})")

    def add_address(self, addr: str, ipv6: bool = False):
        # Hack: shell out to ifconfig, replace this with ioctl in the future?
        # Remove the netmask from the second occurence ("dest", but we don't really use it that way)
        ip = addr.split("/", 1)[0]
        if ipv6:
            subprocess.run(["/sbin/ifconfig", self._ifname, "inet6", addr, "alias"])
            # Hack: add default IPv6 link-local route
            subprocess.run(["/sbin/route", "add", "-inet6", "-ifscope", self._ifname, "default", f"fe80::%{self._ifname}"])
        else:
            # Hack: use IPv4 "point-to-point" address (shows up as "addr -> ip"), dest doesn't actually matter
            subprocess.run(["/sbin/ifconfig", self._ifname, "inet", addr, ip, "alias"])
            # Hack: add default IPv4 route
            subprocess.run(["/sbin/route", "add", "default", "-ifscope", self._ifname, ip])


    def write_packet(self, packet: bytes):
        # utun expects a 4-byte network-order family header before the packet bytes.
        fam = socket.AF_INET6 if packet and (packet[0] >> 4) == 6 else socket.AF_INET
        hdr = fam.to_bytes(4, "big")
        self._sock.sendall(hdr + packet)

    def read_packet(self, size: int = 65536) -> bytes:
        # recv includes 4-byte family header
        data = self._sock.recv(size + 4)
        if len(data) < 4:
            return b''
        return data[4:]

    def ifname(self) -> str:
        return self._ifname

    def close(self):
        self._sock.close()

    def fileno(self) -> int:
        return self._sock.fileno()

def open_tun() -> Tun:
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

    # Example: write an IPv6 packet
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
