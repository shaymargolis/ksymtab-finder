
# find_ksymtab.py

import sys
import re
import struct
from binascii import unhexlify

class KernelBlobFile():
    KSYMTAB_SYMBOLS = [
        "init_task",
        "printk",
        "printk_ratelimit_burst",
        "kernel_neon_begin",
        "kernel_neon_end",
        "sysctl_tcp_mem",
        "tcp_memory_allocated",
        "tcp_have_smc",
        "tcp_sockets_allocated",
        "tcp_rx_skb_cache_key",
        "tcp_init_sock",
        "tcp_poll",
        "tcp_ioctl",
        "tcp_splice_read",
        "tcp_sendpage",
        "tcp_sendmsg",
        "tcp_read_sock",
        "tcp_peek_len",
        "tcp_set_rcvlowat",
        "tcp_mmap",
        "tcp_recvmsg",
        "tcp_shutdown",
        "tcp_close",
        "tcp_disconnect",
        "tcp_tx_delay_enabled",
        "tcp_setsockopt",
        "compat_tcp_setsockopt",
        "tcp_getsockopt",
        "compat_tcp_getsockopt",
        "tcp_alloc_md5sig_pool",
        "tcp_get_md5sig_pool",
        "tcp_md5_hash_skb_data",
        "tcp_md5_hash_key",
    ]

    def __init__(self, filename, bitsize):
        self.endianess = "LE"
        self.bitsize = bitsize

        self.bytes = int(self.bitsize/8)
        self.filename = filename
        self.kernel = b""

        with open(filename, "rb") as f:
            self.kernel = f.read()

    def get_word(self, x):
        flag = "big"
        if self.endianess == "LE":
            flag = "little"

        try:
            return int.from_bytes(self.kernel[x:(x+self.bytes)], flag)
        except Exception as e:
            return None

    def get_long(self, x, signed=False):
        flag = "big"
        if self.endianess == "LE":
            flag = "little"

        try:
            return int.from_bytes(self.kernel[x:(x+4)], flag, signed=signed)
        except Exception as e:
            return None

    def get_string(self, x):
        max_str_size = 200
        try:
            null_terminator = self.kernel.find(b"\0", x+1)
            if null_terminator == -1 or null_terminator >= x+max_str_size:
                return None

            candidate = self.kernel[x:null_terminator].decode()
            if candidate == "\x00":
                return None

            return candidate
        except Exception as e:
            return None

    def find_ksymtab(self):
        return None
