# Based on work by Mario Vilas, http://breakingcode.wordpress.com, licensed under BSD in 2016

import distorm3
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--b16",
        help="80286 decoding",
        action="store_const",
        dest="dt",
        const=distorm3.Decode16Bits,
    )
    parser.add_argument(
        "--b32",
        help="IA-32 decoding [default]",
        action="store_const",
        dest="dt",
        const=distorm3.Decode32Bits,
    )
    parser.add_argument(
        "--b64",
        help="AMD64 decoding",
        action="store_const",
        dest="dt",
        const=distorm3.Decode64Bits,
    )
    parser.add_argument("file",)
    parser.add_argument(
        "offset", type=int, nargs="?",
    )
    parser.set_defaults(dt=distorm3.Decode32Bits)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    offset = args.offset

    # Read the code from the file
    with open(args.file, "rb") as infp:
        code = infp.read()

    # Print each decoded instruction
    # This shows how to use the DecodeGenerator
    iterable = distorm3.DecodeGenerator(offset, code, args.dt)
    for (offset, size, instruction, hexdump) in iterable:
        print("%.8x: %-32s %s" % (offset, hexdump, instruction))

    # It could also be used as a returned list:
    # l = distorm3.Decode(offset, code, options.dt)
    # for (offset, size, instruction, hexdump) in l:
    #     print("%.8x: %-32s %s" % (offset, hexdump, instruction))


if __name__ == "__main__":
    main()
