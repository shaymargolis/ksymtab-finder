
# find_ksymtab.py

import sys
import re
import struct
import click

from binascii import unhexlify
from kernel_accessor import KernelBlobFile

class Rel32KsymtabFinder(KernelBlobFile):
    def __init__(self, filename, bitsize, endianess):
        super().__init__(filename, bitsize, endianess)

    def get_rel32_matches(self, true_index):
        """
        Returns all addresses A in the memory that statifsfies
        
        A+*A = true_index (Taken from 
                           offset_to_ptr()@include/linux/compiler.h 
                           - in the linux kernel)
        """

        matches = []

        for i in range(0, len(self.kernel), 4):
            val = self.get_long(i, signed=True)
            if i + val == true_index:
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

    def _parse_ksymtab(self, address, direction=1):
        REL32_BYTE_SIZE = 4

        addresses = {}

        found_word = self.get_long(address, signed=True)

        while self.get_string(address + found_word):
            value = self.get_long(address - REL32_BYTE_SIZE, signed=True)
            addresses[value + address - REL32_BYTE_SIZE] = self.get_string(address + found_word)

            address += direction * 3 * REL32_BYTE_SIZE
            found_word = self.get_long(address, signed=True)

        return addresses
        
    def parse_ksymtab(self, address):
        res = self._parse_ksymtab(address, direction=1)
        res.update(self._parse_ksymtab(address, direction=-1))

        return res


@click.command()
@click.argument('filename')
@click.argument('bitsize', type=int)
@click.option('--endianess', help='Architecture endianess (LE/BE)', default="LE", show_default=True)
def find_rel32_ksymtab(filename, bitsize, endianess):
    finder = Rel32KsymtabFinder(filename, bitsize, endianess)
    ksymtab = finder.find_ksymtab()
    if ksymtab is None:
        raise Exception("KSYMTAB was not found")

    symbols = finder.parse_ksymtab(ksymtab)

    print(symbols)

if __name__ == '__main__':
    find_rel32_ksymtab()
