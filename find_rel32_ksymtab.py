
# find_ksymtab.py

import sys
import re
import struct
from binascii import unhexlify
from kernel_accessor import KernelBlobFile

class Rel32KsymtabFinder(KernelBlobFile):
    def __init__(self, filename, bitsize):
        super().__init__(filename, bitsize)

    def get_rel32_matches(self, true_index):
        matches = []

        for i in range(0, len(self.kernel), 4):
            val = self.get_long(i, signed=True)
            if i + val == true_index:
                matches.append(i)
        
        return matches

    def find_ksymtab(self):
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

if __name__ == "__main__":
    filename = sys.argv[1]
    bitsize = int(sys.argv[2])

    finder = Rel32KsymtabFinder(filename, bitsize)
    ksymtab = finder.find_ksymtab()
    if ksymtab is None:
        raise Exception("KSYMTAB was not found")

    symbols = finder.parse_ksymtab(ksymtab)

    print(symbols)
