#!/usr/bin/env python
import Headers
import argparse
import os
import sys


def main():
    file_headers = ["DOS", "file", "PE", "sections", "all"]

    parser = argparse.ArgumentParser(description="PE file parser", usage="%(prog)s [options]")
    parser.add_argument("file", nargs=1, help="PE file to parse")
    parser.add_argument("-o", "--options", dest="opt", type=str, choices=file_headers, help="Headers to dump")
    parser.add_argument("-d", "--disassemble", dest="dis", type=str, help="Section to disassemble")

    args = parser.parse_args()
    file = args.file[0]

    if not os.path.exists(file):
        print("File {} doesn't exists.".format(file), file=sys.stderr)
        parser.exit(FileNotFoundError.errno)

    ################## Choices ##################
    if args.opt is not None:
        if args.opt == "DOS":
            Headers.DecodeFile(file).dump_dos()

        elif args.opt == "file":
            Headers.DecodeFile(file).dump_file_hdr()

        elif args.opt == "PE":
            Headers.DecodeFile(file).dump_pe_opt_header()

        elif args.opt == "sections":
            Headers.DecodeFile(file).dump_sections_header()

        elif args.opt == "all":
            Headers.DecodeFile(file).dump_file_info()

    if args.dis is not None:
        Headers.DecodeFile(file).disassemble_section(args.dis)


if __name__ == "__main__":
    main()