
# find_ksymtab.py

import sys
import re
import struct
import click
from construct import Struct

from binascii import unhexlify
from kernel_accessor import KernelBlobFile

class Rel32KsymtabFinder(KernelBlobFile):
    def __init__(self, filename, bitsize, linux_ver, endianess):
        super().__init__(filename, bitsize, linux_ver, endianess)

        arch_long_type = self.get_long_type(signed=True)

        fields = [
            "value" / arch_long_type,
            "name" / arch_long_type,
        ]

        if self.linux_ver >= (5, 3, 0):
            fields += ["namespace" / arch_long_type]

        self.KernelSymbol = Struct(
            *fields
        )

    def _get_rel32_value(self, address):
        val = self.get_long(address, signed=True)
        return val + address

    def get_rel32_matches(self, true_index):
        """
        Returns all addresses A in the memory that statifsfies
        
        A+*A = true_index (Taken from 
                           offset_to_ptr()@include/linux/compiler.h 
                           - in the linux kernel)
        """

        matches = []

        for i in range(0, len(self.kernel), 4):
            if self._get_rel32_value(i) == true_index:
                matches.append(i)
        
        return matches

    def find_ksymtab(self):
        """
        Iterates over all KSYMTAB_SYMBOLS. Then for each string searches the memory
        for the rel32 match of the string: For X location of the string in the memory,
        An address A that statisfies the following:

        A+*A = X (Taken from offset_to_ptr()@include/linux/compiler.h - in the linux kernel)

        If there is only one occurence - This the ksymtab rel32 reference of the string!
        """

        REL32_BYTE_SIZE = 4

        for ksymtab_symbol in self.KSYMTAB_SYMBOLS:
            matches = list(re.finditer(b"\0"+ksymtab_symbol.encode()+b"\0", self.kernel))
            if len(matches) > 1 or len(matches) == 0:
                continue

            true_index = matches[0].start()+1

            rel32_matches = self.get_rel32_matches(true_index)

            if len(rel32_matches) > 1 or len(rel32_matches) == 0:
                print(f"** {ksymtab_symbol} {len(rel32_matches)} are not enough/too much")
                continue

            rel32_match = rel32_matches[0]

            print(f"** Found ksymtab! {ksymtab_symbol} @{hex(rel32_match)} searched for {hex(true_index)}")

            return rel32_match

        # Not found
        return None

    def _get_kernel_symbol(self, x):
        REL32_BYTE_SIZE = 4

        # Parse the struct at the location
        data = self.kernel[x:x+self.KernelSymbol.sizeof()]
        result = self.KernelSymbol.parse(data)

        result["value_addr"] = self._get_rel32_value(x)
        result["name_addr"] = self._get_rel32_value(x + REL32_BYTE_SIZE)

        # Retrieve the name string from memory
        result["name_string"] = self.get_string(result["name_addr"])

        return result

    def _parse_ksymtab(self, address, direction=1):
        addresses = {}

        kernel_symbol = self._get_kernel_symbol(address)

        while kernel_symbol["name_string"]:
            addresses[kernel_symbol["value_addr"]] = kernel_symbol["name_string"]

            address += direction * self.KernelSymbol.sizeof()
            kernel_symbol = self._get_kernel_symbol(address)

        return addresses
        
    def parse_ksymtab(self, address):
        REL32_BYTE_SIZE = 4

        # Get offset of value instead of name inside of kernel_symbol
        ksymtab_address = address - REL32_BYTE_SIZE

        res = self._parse_ksymtab(ksymtab_address, direction=1)
        res.update(self._parse_ksymtab(ksymtab_address, direction=-1))

        return res

    def find_and_parse_ksymtab(self):
        REL32_BYTE_SIZE = 4

        address = self.find_ksymtab()
        if address is None:
            raise Exception("KSYMTAB was not found")

        return self.parse_ksymtab(address)
