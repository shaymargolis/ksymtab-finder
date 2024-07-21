
# find_ksymtab.py

import sys
import re
import struct
import click

from binascii import unhexlify
from kernel_accessor import KernelBlobFile

class KsymtabFinder(KernelBlobFile):
    def __init__(self, filename, bitsize, endianess):
        super().__init__(filename, bitsize, endianess)

    def find_all_ends_with_hex_regular(self, hexstr):
        """
        Finds all occurences of WORD sized integers, that end with
        hexstr. For example, if hexstr is BABE
        the search will return locations of:
            0xFFFFBABE
                0xBABE
            0x8000BABE

        hexstr must be a EVEN length string
        """

        if len(hexstr) % 2 != 0:
            raise Exception("Must use even length hexstr for find_all_ends_with_hex_regular!")

        parts = [hexstr[i:i+2] for i in range(0, len(hexstr), 2)]
        if self.endianess == "LE":
            parts = list(reversed(parts))

        lookup = "".join(parts)
        lookup_bytes = unhexlify(lookup)

        matches = []
        match = self.kernel.find(lookup_bytes)
        while match != -1:
            matches.append(match)
            match = self.kernel.find(lookup_bytes, match+1)

        if self.endianess == "BE":
            # Fix the searches to the beginning of the number
            # For example, when searching for "e7e7"
            # and getting the result ff ff e7 e7
            # we will have a point to 0xe7e7 instead of 0xffffe7e7.

            byte_count = int(len(hexstr)/2)
            byte_fix = self.bytes - byte_count

            matches = list(map(lambda x: x-byte_fix, matches))

        return matches

    def find_all_ends_with_hex_nonregular(self, hexstr):
        """
        Finds all occurences of WORD sized integers, that end with
        hexstr. For example, if hexstr is E7E
        the search will return locations of:
            0xFFFFFE7E
                 0xE7E
            0x80000E7E

        hexstr can be odd-numbered string.
        """

        if len(hexstr) % 2 == 0:
            # Regular find
            return self.find_all_ends_with_hex_regular(hexstr)

        # Special find
        matches = []
        for letter in list("0123456789abcdef"):
            hexstr_letter = letter + hexstr
            matches += self.find_all_ends_with_hex_regular(hexstr_letter)

        return matches

    def find_ksymtab(self):
        """
        Iterates over all KSYMTAB_SYMBOLS. If finds a match, some address in the memory
        with the same page offset as the string, and this is the only one - 
        this must be the ksymtab's string reference. 
        """

        for ksymtab_symbol in self.KSYMTAB_SYMBOLS:
            matches = list(re.finditer(b"\0"+ksymtab_symbol.encode()+b"\0", self.kernel))
            if len(matches) > 1 or len(matches) == 0:
                continue

            PAGE_ALIGN = 0x1000
            PAGE_OFFSET = 3

            true_index = matches[0].start()+1
            lookup_needle = hex(true_index & (PAGE_ALIGN-1))[2:]

            results = self.find_all_ends_with_hex_nonregular(lookup_needle)

            # Align
            results = list(filter(lambda x: x%self.bytes==0, results))

            bitmask = 40 if self.bitsize == 64 else 24

            results = list(filter(
                lambda x: (self.get_word(x) >> bitmask) == (self.get_word(x+self.bytes) >> bitmask)
                , results
            ))

            print(
                "**",
                ksymtab_symbol,
                true_index,
                lookup_needle,
                [(x, hex(self.get_word(x))) for x in results]
            )

            if len(results) != 1:
                continue

            reloc_addr = self.get_word(results[0]) - true_index
            print("\t! Base address is", hex(reloc_addr))

            return results[0], reloc_addr

        # Not found
        return None

    def _parse_ksymtab(self, address, reloc_addr, direction=1):
        # TODO: This is (2*REL32_BYTE_SIZE) in older kernel versions
        STRUCT_KERNEL_SYMBOL_SIZE = 3 * self.bytes

        addresses = {}

        found_word = self.get_word(address)

        print(hex(found_word), hex(reloc_addr))

        while self.get_string(found_word - reloc_addr):
            value = self.get_word(address - self.bytes)
            addresses[value] = self.get_string(found_word - reloc_addr)

            address += direction * STRUCT_KERNEL_SYMBOL_SIZE
            found_word = self.get_word(address)

        return addresses
        
    def parse_ksymtab(self, address, reloc_addr):
        res = self._parse_ksymtab(address, reloc_addr, direction=1)
        res.update(self._parse_ksymtab(address, reloc_addr, direction=-1))

        return res


@click.command()
@click.argument('filename')
@click.argument('bitsize', type=int)
@click.option('--endianess', help='Architecture endianess (LE/BE)', default="LE", show_default=True)
def find_ksymtab(filename, bitsize, endianess):
    finder = KsymtabFinder(filename, bitsize, endianess)
    result = finder.find_ksymtab()
    if result is None:
        raise Exception("KSYMTAB was not found")

    ksymtab, reloc_addr = result
    symbols = finder.parse_ksymtab(ksymtab, reloc_addr)

    print(symbols)

if __name__ == '__main__':
    find_ksymtab()
