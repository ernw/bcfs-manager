from . import FileSystem

def test():
    import sys
    from pprint import pprint

    offset = 0
    if len(sys.argv) > 2:
        if sys.argv[2].lower().startswith('0x'):
            offset = int(sys.argv[2][2:], 16)
        elif sys.argv[2].endswith('h'):
            offset = int(sys.argv[2][:-1], 16)
        else:
            offset = int(sys.argv[2])

    with open(sys.argv[1], 'rb') as fp:
        fs = FileSystem(fp)
        if not fs.read_string_and_config_table(offset):
            print("No valid records at offset 0x{:X}".format(offset))

        print("\nStrings\n" + "#"*80)
        pprint(fs.strings)
        print("\nConfigs\n" + "#"*80)
        pprint(fs.configs)
        print("\nSignature\n" + "#"*80)
        pprint(fs.signature)

        partitions = fs.get_partitions()
        pprint(partitions)


if __name__ == "__main__":
    test()