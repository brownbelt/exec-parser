# -*- coding: utf-8 -*-
from time import ctime
from binascii import hexlify
import capstone
import ctypes
import struct


class DOS_HEADER(ctypes.Structure):
    """ MS-DOS file header """
    _fields_ = [
        ("signature",                       ctypes.c_char * 2),
        ("last_size",                       ctypes.c_ushort),
        ("n_blocks",                        ctypes.c_ushort),
        ("n_reloc",                         ctypes.c_ushort),
        ("hdr_size",                        ctypes.c_ushort),
        ("min_alloc",                       ctypes.c_ushort),
        ("max_alloc",                       ctypes.c_ushort),
        ("ss",                              ctypes.c_ushort),
        ("sp",                              ctypes.c_ushort),
        ("checksum",                        ctypes.c_ushort),
        ("ip",                              ctypes.c_ushort),
        ("cs",                              ctypes.c_ushort),
        ("relocpos",                        ctypes.c_ushort),
        ("noverlay",                        ctypes.c_ushort),
        ("res",                             ctypes.c_ushort * 4),
        ("oem_id",                          ctypes.c_ushort),
        ("oem_info",                        ctypes.c_ushort),
        ("res2",                            ctypes.c_ushort * 10),
        ("e_lfanew",                        ctypes.c_uint),
    ]

    def __new__(self, file_buffer):
        return self.from_buffer_copy(file_buffer)

    def __init__(self, file_buffer):
        pass

    def __str__(self):

        return self.e_lfanew


class FILE_HEADER(ctypes.Structure):
    """ Decodes the COFF file header """
    _fields_ = [
        ("name",                          ctypes.c_char * 4),     # 'PE\0\0' Signature
        ("machine",                       ctypes.c_ushort),       # Identifies the type of target machine.
        ("number_of_sections",            ctypes.c_ushort),       # Indicates the number of sections.
        ("timedatestamp",                 ctypes.c_uint),         # The low 32 bits, indicates when the file was created (00:00 Jan 1, 1970)
        ("ptr_symbol_table",              ctypes.c_uint),         # The file offset of the COFF symbol table (Deprecated).
        ("number_of_symbols",             ctypes.c_uint),         # The number of entries in the symbol table (Deprecated)
        ("size_opt_hdr",                  ctypes.c_ushort),       # The size of the optional header, required for executable files.
        ("characteristics",               ctypes.c_ushort)        # The flags that indicate the attributes of the file.
    ]

    MACHINE_ARCHS = { # Known machine architectures
        0x14c: "Intel 386",
        0x8664: "x64",
        0x162: "MIPS R3000",
        0x168: "MIPS R10000",
        0x169: "MIPS little endian WCI v2",
        0x183: "Old Alpha AXP",
        0x184: "Alpha AXP",
        0x1a2: "Hitachi SH3",
        0x1a3: "Hitachi SH3 DSP",
        0x1a6: "Hitachi SH4",
        0x1a8: "Hitachi SH8",
        0x1c0: "ARM little endian",
        0x1c2: "Thumb",
        0x1c4: "ARMv7",
        0x1d3: "Matsushita AM33",
        0x1f0: "PowerPC little endian",
        0x1f1: "PowerPC with floating point support",
        0x200: "Intel IA64",
        0x266: "MIPS16",
        0x268: "Motorola 68000 series",
        0x284: "Alpha AXP 64-bit",
        0x366: "MIPS with FPU",
        0x466: "MIPS16 with FPU",
        0xebc: "EFI Byte Code",
        0x8664: "AMD AMD64",
        0x9041: "Mitsubishi M32R little endian",
        0xaa64: "ARM64 little endian",
        0xc0ee: "clr pure MSIL"
    }

    CHARACTERISTICS = {             # Decode values of the 'characteristics' field.
        0x0001 : "Relocation information was stripped from file.\n",
        0x0002 : "The file is executable.\n",
        0x0004 : "COFF line numbers were stripped from file.\n",
        0x0008 : "COFF symbol table entries were stripped from file.\n",
        0x0010 : "Aggressively trim the working set (Obsolete).\n",
        0x0020 : "The application can handle addresses greater than 2GB.\n" ,
        0x0040 : "",
        0x0080 : "The bytes of the word are reversed (Obsolete).\n",
        0x0100 : "The computer supports 32-bit words.\n",
        0x0200 : "Debugging information was removed and stored in another file.\n",
        0x0400 : "Image on removable media, copy it to and run it from the swap file.\n",
        0x0800 : "Image is on the network, copy it to and run it from the swap file.\n",
        0x1000 : "Image is a system file.\n",
        0x2000 : "Image is a DLL file.\n",
        0x4000 : "Image should be ran on a single processor computer.\n",
        0x8000 : "The bytes of the word are reversed (Obsolete).\n"
    }


    def __new__(self, file_buffer):
        return self.from_buffer_copy(file_buffer)

    def __init__(self, file_buffer):
        self.arch = self.MACHINE_ARCHS[self.machine]
        self.time = ctime(self.timedatestamp)

    def get_characteristics(self):
        """ Return a readable output of the characteristics of the provided file. """
        c = list()

        # Check each bit position to find a match on the registered 'characteristics' value.
        for bit_position in range(1, 17):
            if (1 & (self.characteristics >> bit_position)) == 1:
                c.append(self.CHARACTERISTICS[2 ** bit_position])

        return "".join(c)


class _Data_Directory(ctypes.Structure):
    _fields_ = [
        ("virtual_address",              ctypes.c_uint),
        ("size",                         ctypes.c_uint)
    ]


class PE_OPT_HEADER_64(ctypes.Structure):
    """ Decodes the 64-bits version of the PE file "not-so-optional" header. """
    _fields_ = [
        ("signature",                     ctypes.c_ushort),
        ("major_linker_version",          ctypes.c_char),             # The major version number of the linker.
        ("minor_linker_version",          ctypes.c_char),             # The minor version number of the linker.
        ("size_of_code",                  ctypes.c_uint),             # The size of the code section, in bytes, or the sum of all [data] sections.
        ("size_of_init_data",             ctypes.c_uint),             # The size of the initialized data section, in bytes, or the sum of all [init] sections.
        ("size_of_uninit_data",           ctypes.c_uint),             # The size of the uninitialized data section, in bytes, or the sum of all [uninit] sections
        ("addr_of_entry_point",           ctypes.c_uint),             # A pointer to the entry point function, relative to the image address.
        ("base_of_code",                  ctypes.c_uint),             # A pointer to the beginning of the code section, relative to the image base.
        # The next 21 fields are an extension to the COFF optional header format.
        ("image_base",                    ctypes.c_ulong),            # The preferred address of the first byte of the image when it is loaded in memory.
        ("section_alignment",             ctypes.c_uint),             # The alignment of sections loaded in memory, in bytes.
        ("file_alignment",                ctypes.c_uint),             # The alignment of the raw data of sections in the image file, in bytes.
        ("major_os_version",              ctypes.c_ushort),           # The major version number of the required operating system.
        ("minor_os_ersion",               ctypes.c_ushort),           # The minor version number of the required operating system.
        ("major_img_version",             ctypes.c_ushort),           # The major version number of the image.
        ("minor_img_version",             ctypes.c_ushort),           # The minor version number of the image.
        ("major_subsys_version",          ctypes.c_ushort),           # The major version number of the subsystem.
        ("minor_subsys_version",          ctypes.c_ushort),           # The minor version number of the subsystem.
        ("win32_version_value",           ctypes.c_uint),             # Reserved.
        ("size_of_image",                 ctypes.c_uint),             # The size of the image, in bytes, including all headers
        ("size_of_headers",               ctypes.c_uint),             # The combined size of the MS_DOS stub, PE header and section headers.
        ("checksum",                      ctypes.c_uint),             # The image file checksum.
        ("subsystem",                     ctypes.c_ushort),           # The subsystem that will be invoked to run the executable.
        ("dll_characteristics",           ctypes.c_ushort),           # DLL characteristics of the image.
        ("size_of_stack_reserve",         ctypes.c_ulong),            # The number of bytes to reserve for the stack.
        ("size_of_stack_commit",          ctypes.c_ulong),            # The number of bytes to commit for the stack.
        ("size_of_heap_reserve",          ctypes.c_ulong),            # The number of bytes to reserve for the local heap.
        ("size_of_heap_commit",           ctypes.c_ulong),            # The number of bytes to commit for the local heap.
        ("loader_flags",                  ctypes.c_uint),             # Obsolete
        ("number_of_rva_and_sizes",       ctypes.c_uint),             # Number of directory entries in the remainder of the optional header.
        ("data_directory",                _Data_Directory * 16)       # Provides RVAs and sizes which locate various data structures.
    ]

    subsystems_dec = {           # Contains readable information about the provided subsystem field.
        0 : "Unknown subsystem",
        1 : "No subsystem required (Device driver or native system process)",
        2 : "GUI subsystem",
        3 : "CLI subsystem",
        5 : "OS/2 CLI subsystem",
        6 : "",
        7 : "POSIX CLI subsystem",
        8 : "",
        9 : "Windows CE system",
        10 : "EFI application",
        11 : "EFI driver with boot services",
        12 : "EFI driver with run-time services",
        13 : "EFI ROM image",
        14 : "Xbox system",
        15 : "",
        16 : "Boot application"
    }

    dll_characteristics_dec = {           # Contains readable information of the DLL characteristics of the image.
        0x0001 : "",
        0x0002 : "",
        0x0004 : "",
        0x0008 : "",
        0x0040 : "DLL can be relocated at load time.\n",
        0x0080 : "Code integrity checks are forced.\n",
        0x0100 : "Image is compatible with data execution prevention (DEP).\n",
        0x0200 : "Image is isolation aware, but should not be isolated.\n",
        0x0400 : "Image does not use structures exception handling (SEH).\n",
        0x0800 : "Do not bind the image.\n",
        0x1000 : "",
        0x2000 : "A WDM driver",
        0x4000 : "",
        0x8000 : "Image is terminal server aware.\n"
    }

    def __new__(self, file_buffer):
        return self.from_buffer_copy(file_buffer)

    def __init__(self, file_buffer):
        self.dllChars = self.get_dll_characteristics()
        self.subsys = self.get_subsystem()

    def get_dll_characteristics(self):
        """ Produce a readable output of the dll characteristics of the image. """
        c = list()

        for bit_position in range(1, 16):
            if 1 & (self.dll_characteristics >> bit_position):
                c.append(self.dll_characteristics_dec[2 ** bit_position])

        return "".join(c)

    def get_subsystem(self):
        """ Returns the required subsytem to execute the file. """
        for bit_position in range(0, 17):
            if 1 & (bit_position >> bit_position):
                return self.subsystemsDec[2 ** bit_position]


class PE_OPT_HEADER_32(ctypes.Structure):
    """ Decodes the 32-bits version of the PE file "not-so-optional" header. """
    _fields_ = [
        ("signature",                      ctypes.c_ushort),
        ("major_linker_version",           ctypes.c_char),
        ("minor_linker_version",           ctypes.c_char),
        ("size_of_code",                   ctypes.c_uint),
        ("size_of_init_data",              ctypes.c_uint),
        ("size_of_uninit_data",             ctypes.c_uint),
        ("addr_of_entry_point",            ctypes.c_uint),
        ("base_of_code",                   ctypes.c_uint),
        ("base_of_data",                   ctypes.c_uint),             # A pointer to the beginning of the data section, relative to the image base.
        # The next 21 fields are an extension to the COFF optional header format.
        ("image_base",                     ctypes.c_uint),
        ("section_alignment",              ctypes.c_uint),
        ("file_alignment",                 ctypes.c_uint),
        ("major_os_version",               ctypes.c_ushort),
        ("minor_os_version",               ctypes.c_ushort),
        ("major_img_version",              ctypes.c_ushort),
        ("minor_img_version",              ctypes.c_ushort),
        ("major_subsys_version",           ctypes.c_ushort),
        ("minor_subsys_version",           ctypes.c_ushort),
        ("win32_version_value",            ctypes.c_uint),
        ("size_of_image",                  ctypes.c_uint),
        ("size_of_headers",                ctypes.c_uint),
        ("checksum",                       ctypes.c_uint),
        ("subsystem",                      ctypes.c_ushort),
        ("dll_characteristics",            ctypes.c_ushort),
        ("size_of_stack_reserve",          ctypes.c_uint),
        ("size_of_stack_commit",           ctypes.c_uint),
        ("size_of_heap_reserve",           ctypes.c_uint),
        ("size_of_heap_commit",            ctypes.c_uint),
        ("loader_flags",                   ctypes.c_uint),
        ("number_of_rva_and_sizes",        ctypes.c_uint),
        ("data_directory",                 _Data_Directory * 16)
    ]

    subsystems_dec = {           # Information about the provided subsystem field.
        0 : "Unknown subsystem",
        1 : "No subsystem required (Device driver or native system process)",
        2 : "GUI subsystem",
        3 : "CLI subsystem",
        5 : "OS/2 CLI subsystem",
        6 : "",
        7 : "POSIX CLI subsystem",
        8 : "",
        9 : "Windows CE system",
        10 : "EFI application",
        11 : "EFI driver with boot services",
        12 : "EFI driver with run-time services",
        13 : "EFI ROM image",
        14 : "Xbox system",
        15 : "",
        16 : "Boot application"
    }

    dll_characteristics_dec = {           # Information of the DLL characteristics of the image.
        0x0001 : "",
        0x0002 : "",
        0x0004 : "",
        0x0008 : "",
        0x0040 : "DLL can be relocated at load time.\n",
        0x0080 : "Code integrity checks are forced.\n",
        0x0100 : "Image is compatible with data execution prevention (DEP).\n",
        0x0200 : "Image is isolation aware, but should not be isolated.\n",
        0x0400 : "Image does not use structures exception handling (SEH).\n",
        0x0800 : "Do not bind the image.\n",
        0x1000 : "",
        0x2000 : "A WDM driver",
        0x4000 : "",
        0x8000 : "Image is terminal server aware.\n"
    }

    def __new__(self, file_buffer):
        return self.from_buffer_copy(file_buffer)

    def __init__(self, file_buffer):
        self.dll_chars = self.get_dll_characteristics()
        self.subsys = self.get_subsystem()

    def get_dll_characteristics(self):
        """ Produce a readable output of the dll characteristics of the image. """
        c = list()

        for bit_position in range(1, 16):
            if 1 & (self.dll_characteristics >> bit_position):
                c.append(self.dll_characteristicsDec[2 ** bit_position])

        return "".join(c)

    def get_subsystem(self):
        """ Returns the required subsytem to execute the file. """
        for bit_position in range(0, 17):
            if 1 & (self.subsystem >> bit_position) == 1:
                return self.subsystems_dec[bit_position]


class Misc(ctypes.Union):
    _fields_ = [
        ("physical_address",         ctypes.c_uint),
        ("virtual_size",             ctypes.c_uint)
    ]


class IMAGE_SECTION_HEADER(ctypes.Structure):
    """ Decodes the information contained in the file sections. """
    _fields_ = [
        ("name",                            ctypes.c_char * 8),
        ("misc",                            Misc),
        ("virtual_address",                 ctypes.c_uint),
        ("size_of_raw_data",                ctypes.c_uint),
        ("ptr_to_raw_data",                 ctypes.c_uint),
        ("ptr_to_reloc",                    ctypes.c_uint),
        ("ptr_to_line_numbers",             ctypes.c_uint),
        ("number_of_reloc",                 ctypes.c_ushort),
        ("number_of_line_numbers",          ctypes.c_ushort),
        ("characteristics",                 ctypes.c_uint)
    ]

    characteristics_dec = {                  # Readable state of the 'section characteristics' flags.
                0x00000000 : "",
                0x00000001 : "",
                0x00000002 : "",
                0x00000004 : "",
                0x00000008 : "Section should not be padded to the next boundary.\n",
                0x00000010 : "",
                0x00000020 : "Section contains executable code.\n",
                0x00000040 : "Section contains initialized data.\n",
                0x00000080 : "Section contains uninitialized data.\n",
                0x00000100 : "",
                0x00000200 : "Section contains comments or other information.\n",
                0x00000400 : "",
                0x00000800 : "Section will not become part of the image.\n",
                0x00001000 : "Section contains COMDAT data.\n",
                0x00002000 : "",
                0x00004000 : "Reset speculative exceptions handling bits in the TLB entries for this section.\n",
                0x00008000 : "Section contains data referenced through the global pointer.\n",
                0x00010000 : "",
                0x00020000 : "",
                0x00040000 : "",
                0x00080000 : "",
                0x00100000 : "Align data on a 1-byte boundary.\n",
                0x00200000 : "Align data on a 2-byte boundary.\n",
                0x00300000 : "Align data on a 4-byte boundary.\n",
                0x00400000 : "Align data on a 8-byte boundary.\n",
                0x00500000 : "Align data on a 16-byte boundary.\n",
                0x00600000 : "Align data on a 32-byte boundary.\n",
                0x00700000 : "Align data on a 64-byte boundary.\n",
                0x00800000 : "Align data on a 128-byte boundary.\n",
                0x00900000 : "Align data on a 256-byte boundary.\n",
                0x00A00000 : "Align data on a 512-byte boundary.\n",
                0x00B00000 : "Align data on a 1024-byte boundary.\n",
                0x00C00000 : "Align data on a 2048-byte boundary.\n",
                0x00D00000 : "Align data on a 4096-byte boundary.\n",
                0x00E00000 : "Align data on a 8192-byte boundary.\n",
                0x01000000 : "Section contains extended relocations.\n",
                0x02000000 : "Section can be discarded as needed.\n",
                0x04000000 : "Section cannot be cached.\n",
                0x08000000 : "Section cannot be paged.\n",
                0x10000000 : "Section can be shared in memory.\n",
                0x20000000 : "Section can be executed as code.\n",
                0x40000000 : "Section can be read.\n",
                0x80000000 : "Section can be written to."
            }

    def __new__(self, file_buffer):
        return self.from_buffer_copy(file_buffer)

    def __init__(self, file_buffer):
        self.sectionChars = self.get_characteristics()

    def get_characteristics(self):
        """ Produce a readable output of the characteristics of the provided section. """
        c = list()

        for bit_position in range(1, 33):
            if 1 & (self.characteristics >> bit_position) == 1:
                c.append(self.characteristics_dec[2 ** bit_position])

        return "".join(c)


class UnknownSignature(Exception):
    """ Unknown PE file signature error. """
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)


class DecodeFile:
    """ Get information about the provided PE file.
        Params:
        <b>file</b>: The PE file to read.<br>
    """
    def __init__(self, file):
        self.__file = open(file, "rb")

    def __del__(self):
        return self.__file.close()

    def __save_offset(self):
        # Save current file offset.
        return self.__file.tell()

    def __get_section_offset(self):
        offset = self.get_pe_entry_point() + ctypes.sizeof(FILE_HEADER)

        if self.get_file_arch_type() == 0x10b:
            offset += ctypes.sizeof(PE_OPT_HEADER_32)
        else:
            offset += ctypes.sizeof(PE_OPT_HEADER_64)

        return offset

    def is_valid_pe_file(self):
        cur_offset = self.__save_offset()

        self.__file.seek(0)

        signature = self.__file.read(2)

        if struct.unpack("<2c", signature) != (b'M', b'Z'):
            raise UnknownSignature("Error: {} unknown signature.".format(signature))

        # Set the file offset to it's original position.
        self.__file.seek(cur_offset)

        return True

    def get_pe_entry_point(self):
        cur_offset = self.__save_offset()

        # Set the file offset to the beginning of the file
        # and get the PE entry point.
        self.__file.seek(0)
        cont = self.__file.read(ctypes.sizeof(DOS_HEADER))[60:]
        e_lfanew = struct.unpack("<I", cont)[0]

        # Set the file offset to it's original position.
        self.__file.seek(cur_offset)

        return e_lfanew

    def get_num_sections(self):
        """ Returns the number of sectors that the provided Pe file has."""
        # Save file offset.
        cur_offset = self.__save_offset()

        # Get PE entry point.
        e_lfanew = self.get_pe_entry_point()

        self.__file.seek(e_lfanew)

        num_sectors = self.__file.read(8)[6:8]

        self.__file.seek(cur_offset)

        # Return number of sectors
        return struct.unpack("<H", num_sectors)[0]

    def get_file_arch_type(self):
        save_offset = self.__save_offset()

        # Set the file offset at the 'PE_OPTIONAL_HEADER' structure.
        pe_offset = self.get_pe_entry_point() + ctypes.sizeof(FILE_HEADER)
        self.__file.seek(pe_offset)

        file_signature = struct.unpack("<H", self.__file.read(2))[0]

        self.__file.seek(save_offset)
        return file_signature

    #                Parsers
    def parse_dos_header(self):
        """
        Parse the start of the file
        :return: Returns a structure of the first 64 bytes of a PE file.
        """
        self.__file.seek(0)
        dos_hdr_size = ctypes.sizeof(DOS_HEADER)
        dos_hdr = DOS_HEADER(self.__file.read(dos_hdr_size))

        if not self.is_valid_pe_file():
            raise UnknownSignature("Error: {} invalid file signature.".format(dos_hdr.signature))

        return dos_hdr

    def parse_file_header(self):
        file_hdr_size = ctypes.sizeof(FILE_HEADER)
        self.__file.seek(self.get_pe_entry_point())

        return FILE_HEADER(self.__file.read(file_hdr_size))

    def parse_pe_opt_header(self):

        file_signature = self.get_file_arch_type()

        pe_offset = self.get_pe_entry_point() + ctypes.sizeof(FILE_HEADER)
        pe_opt_hdr = None

        self.__file.seek(pe_offset)

        if file_signature == 0x10b:
            size = ctypes.sizeof(PE_OPT_HEADER_32)
            pe_opt_hdr = PE_OPT_HEADER_32(self.__file.read(size))

        elif file_signature == 0x20b:
            size = ctypes.sizeof(PE_OPT_HEADER_64)
            pe_opt_hdr = PE_OPT_HEADER_64(self.__file.read(size))

        else:
            raise UnknownSignature("Error: {} unknown signature.".format(file_signature))

        return pe_opt_hdr, size

    def parse_data_directory(self):
        directories = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
                       "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR",
                       "TLS", "LOAD_CONFIG", "Bound IAT", "IAT", "Delay IAT",
                       "CLR Header", ""
                       ]
        r = dict()
        inx = 0

        for directory in directories:
            r[directory] = self.parse_pe_opt_header()[0].data_directory[inx]
            inx += 1

        return r

    def parse_section_headers(self):
        sections = dict()
        self.__file.seek(self.__get_section_offset())

        for section in range(0, self.get_num_sections()):
            section_size = ctypes.sizeof(IMAGE_SECTION_HEADER)
            section_hdr = IMAGE_SECTION_HEADER(self.__file.read(section_size))
            name = section_hdr.name.decode()

            sections[name] = section_hdr

        return sections

    #                   Dumpers
    def dump_dos(self):
        dos_hdr = self.parse_dos_header()

        print("\n------------------ DOS header ------------------\n")
        print("Signature: {}".format(dos_hdr.signature))
        print("Bytes on last page of file: 0x{:04X}".format(dos_hdr.last_size))
        print("Pages in file: 0x{:04X}".format(dos_hdr.n_blocks))
        print("Number of relocations: 0x{:04X}".format(dos_hdr.n_reloc))
        print("Size of header in paragraphs: 0x{:04X}".format(dos_hdr.hdr_size))
        print("Minimum paragraphs: {0:04X} -> Maximum paragraphs: 0x{1:04X}".format(dos_hdr.min_alloc, dos_hdr.max_alloc))
        print("Initial SS value: 0x{:04X}".format(dos_hdr.ss))
        print("Initial SP value: 0x{:04X}".format(dos_hdr.sp))
        print("Checksum: 0x{:04X}".format(dos_hdr.checksum))
        print("Initial IP value: 0x{:04X}".format(dos_hdr.ip))
        print("Initial CS value: 0x{:04X}".format(dos_hdr.cs))
        print("Relocation table address: 0x{:04X}".format(dos_hdr.relocpos))
        print("Overlay number: 0x{:04X}".format(dos_hdr.noverlay))
        print("OEM identifier: 0x{0:04X} -> OEM info: 0x{1:04X}".format(dos_hdr.oem_id, dos_hdr.oem_info))
        print("Address of exe header: 0x{:08X}".format(dos_hdr.e_lfanew))

    def dump_file_hdr(self):
        file_hdr = self.parse_file_header()

        print("\n------------------ File header ------------------\n")
        print("Signature: {}".format(file_hdr.name))
        print("Target machine: {}".format(file_hdr.arch))
        print("Number of sections: 0x{:04X}".format(file_hdr.number_of_sections))
        print("Date of creation: {}".format(file_hdr.time))
        print("Size of the optional header: 0x{:04X}".format(file_hdr.size_opt_hdr))
        print("Characteristics: {}".format(file_hdr.get_characteristics()))

    def __dump_data_directory(self):
        print("\n-------------------- Data directories -------------------\n")
        for key, value in self.parse_data_directory().items():
            if value.virtual_address != 0x00000000:
                rva = self.get_pe_entry_point() + value.virtual_address
                print("{0:12s} -------> Rva: 0x{1:08X} Size: 0x{2:08X}".format(key, rva, value.size))

    def __dump32(self, hdr):
        major = hexlify(hdr.major_linker_version).decode()
        minor = hexlify(hdr.minor_linker_version).decode()

        print("\n-------------------------- PE file optional header (32 bits) --------------------------\n")
        print("Linker version: {0}/{1}".format(major, minor))
        print("Size of the code section: 0x{:08X}".format(hdr.size_of_code))
        print("Size of the data section: 0x{:08X}".format(hdr.size_of_init_data))
        print("Size of the uninitialized data: 0x{:08X}".format(hdr.size_of_uninit_data))
        print("Address of the entry point: 0x{:08X}".format(hdr.addr_of_entry_point))
        print("Address of the code section: 0x{:08X}".format(hdr.base_of_code))
        print("Address of the data section: 0x{:08X}".format(hdr.base_of_data))

        print("\n-------------------------- Extension of the COFF header --------------------------\n")
        print("Address of the image (In memory): 0x{:08X}".format(hdr.image_base))
        print("Alignment of sections loaded: 0x{:08X}".format(hdr.section_alignment))
        print("Alignment of raw data: 0x{:08X}".format(hdr.file_alignment))
        print("Required OS version: {0}/{1}".format(hdr.major_os_version, hdr.minor_os_version))
        print("Version of the image: {0}/{1}".format(hdr.major_img_version, hdr.minor_img_version))
        print("Subsystem version: {0}/{1}".format(hdr.major_subsys_version, hdr.minor_subsys_version))
        print("Image size: 0x{:08X}".format(hdr.size_of_image))
        print("Headers size: 0x{:08X}".format(hdr.size_of_headers))
        print("Checksum: 0x{:08X}".format(hdr.checksum))
        print("Subsystem to be invoked by the executable: {}".format(hdr.get_subsystem()))
        print("DLL characteristics: {}".format(hdr.get_dll_characteristics()))
        print("Bytes to reserve for the stack: 0x{0:08x} -> ".format(hdr.size_of_stack_reserve), end="")
        print("Bytes to commit: 0x{:08X}".format(hdr.size_of_stack_commit))

        print("Bytes to reserve for the local heap: 0x{0:08X} -> ".format(hdr.size_of_heap_reserve), end="")
        print("Bytes to commit: 0x{:08X}".format(hdr.size_of_heap_commit))

        print("Number of directory entries: 0x{:08X}".format(hdr.number_of_rva_and_sizes))

        self.__dump_data_directory()

    def __dump64(self, hdr):
        major = hexlify(hdr.major_linker_version).decode()
        minor = hexlify(hdr.minor_linker_version).decode()

        print("\n-------------------------- PE file optional header (64 bits) --------------------------\n")
        print("Linker version: {0}/{1}".format(major, minor))
        print("Size of the code section: 0x{:08X}".format(hdr.size_of_code))
        print("Size of the data section: 0x{:08X}".format(hdr.size_of_init_data))
        print("Size of the uninitialized data: 0x{:08X}".format(hdr.size_of_uninit_data))
        print("Address of the entry point: 0x{:08X}".format(hdr.addr_of_entry_point))
        print("Address of the code section: 0x{:08X}".format(hdr.base_of_code))

        print("\n-------------------------- Extension of the COFF header --------------------------\n")
        print("Address of the image (In memory): 0x{:016X}".format(hdr.image_base))
        print("Alignment of sections loaded: 0x{:08X}".format(hdr.section_alignment))
        print("Alignment of raw data: 0x{:08X}".format(hdr.file_alignment))
        print("Required OS version: {0} -> {1}".format(hdr.major_os_version, hdr.minor_os_version))
        print("Version of the image: {0} -> {1}".format(hdr.major_img_version, hdr.minor_img_version))
        print("Subsystem version: {0} -> {1}".format(hdr.major_subsys_version, hdr.minor_subsys_version))
        print("Image size: 0x{:08X}".format(hdr.size_of_image))
        print("Headers size: 0x{:08X}".format(hdr.size_of_headers))
        print("Checksum: 0x{:08X}".format(hdr.checksum))
        print("Subsystem to be invoked by the executable: {}".format(hdr.get_subsystem()))
        print("DLL characteristics: {}".format(hdr.get_dll_characteristics()))
        print("Bytes to reserve for the stack: 0x{0:016x} -> ".format(hdr.size_of_stack_reserve), end="")
        print("Bytes to commit: 0x{:016X}".format(hdr.size_of_stack_commit))

        print("Bytes to reserve for the local heap: 0x{0:016X} -> ".format(hdr.size_of_heap_reserve), end="")
        print("Bytes to commit: 0x{:016X}".format(hdr.size_of_heap_commit))

        print("Number of directory entries: 0x{:08X}".format(hdr.number_of_rva_and_sizes))

        self.__dump_data_directory()

    def dump_pe_opt_header(self):
        pe_file_opt_hdr = self.parse_pe_opt_header()

        if pe_file_opt_hdr[1] <= 224:
            self.__dump32(pe_file_opt_hdr[0])
        else:
            self.__dump64(pe_file_opt_hdr[0])

    def dump_sections_header(self):
        section_hdr = self.parse_section_headers()

        print("\n-------------------- Section headers --------------------\n")

        for section in section_hdr.values():
            print("Section name: {}".format(section.name))
            print("Virtual address to which load the section: 0x{:08X}".format(section.virtual_address))
            print("File-segment relative size: 0x{:08X}".format(section.size_of_raw_data))
            print("Offset to the location of the section body: 0x{:08X}".format(section.ptr_to_raw_data))
            print("Section characteristics: {}\n".format(section.get_characteristics()))

    def dump_file_info(self):
        """ Dumps information about the four sectors of the provided PE file """
        self.dump_dos()
        self.dump_file_hdr()
        self.dump_pe_opt_header()
        self.dump_sections_header()

    def dump_section(self, section_name):
        cur_offset = self.__save_offset()
        d = self.parse_section_headers()

        if not section_name in d.keys():
            raise KeyError("{} is not a key.".format(section_name))

        section_hdr = d[section_name]
        self.__file.seek(section_hdr.ptr_to_raw_data)

        return self.__file.read(section_hdr.size_of_raw_data)

    def disassemble_section(self, section_name):
        cur_offset = self.__save_offset()
        d = self.parse_section_headers()

        if not section_name in d.keys():
            raise KeyError("{} is not a key.".format(section_name))

        section_hdr = d[section_name]
        self.__file.seek(section_hdr.ptr_to_raw_data)

        arch = capstone.CS_MODE_32 if self.get_file_arch_type() == 0x10b else capstone.CS_MODE_64
        md = capstone.Cs(capstone.CS_ARCH_X86, arch)
        data_size = section_hdr.size_of_raw_data
        ptr_raw_data = section_hdr.ptr_to_raw_data

        print("\n--------------Disassembling {} section--------------".format(section_name))

        for (address, s, mnemonic, opt_str) in md.disasm_lite(self.__file.read(data_size), ptr_raw_data):
                print("0x{0:08x}\t{1}\t{2}".format(address, mnemonic, opt_str))
