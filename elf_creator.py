import tempfile
import subprocess


class ELFCreator():
	def __init__(self, arch, bitsize, endianess, base_address, symbols):
		endianess_str = "little"
		if endianess == "BE":
			endianess_str = "big"

		self.elf_output = f"elf{bitsize}-{endianess_str}{arch}"
		self.symbols = symbols
		self.base_address = base_address

	def create_elf(self, in_file, out_file):
		file = tempfile.NamedTemporaryFile()
		filename = file.name

		syms_file = tempfile.NamedTemporaryFile()
		syms_filename = syms_file.name

		symbols = []

		with open(syms_filename, "w") as f:
			for addr, sym in self.symbols.items():
				symbols += ["--add-symbol", f"{sym}={hex(addr)}"]

		subprocess.check_call([
			"objcopy",
			"-I",
			"binary",
			"-O",
			self.elf_output,
			in_file,
			filename,
		])

		subprocess.check_call([
			"objcopy",
			"--rename-section",
			".data=.text",
			"--set-section-flags",
			".data=alloc,code,load",
			"--change-section-address",
			f".data={hex(self.base_address)}",
			filename,
			out_file,
		] + symbols)
