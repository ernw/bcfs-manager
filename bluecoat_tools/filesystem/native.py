from ctypes import *

class HeaderMixin(object):
    _fields_ = [
        ('magic1', c_char*4),
        ('hdr_unknown', c_uint),
        ('size', c_ushort),
        ('hdr_unknown2', c_ushort),
        ('magic2', c_char*4)
    ]
    expected_magic1 = None
    expected_magic2 = None

    def __repr__(self):
        args = [
            '{}={!r}'.format(k, getattr(self, k)) for k, v in self._fields_
        ]
        args.append('valid={}'.format(self.valid))
        return '{}({})'.format(type(self).__name__, ', '.join(args))

    @property
    def valid(self):
        return (not self.expected_magic1 or self.expected_magic1 == self.magic1) and \
               (not self.expected_magic2 or self.expected_magic2 == self.magic2)

    @classmethod
    def to_r2(cls):
        formats = []
        names = []
        result = []
        for name, dtype in cls._fields_:
            fmt = ''
            if hasattr(dtype, '_length_'): # array
                fmt += '[{}]'.format(dtype._length_)
            t = dtype
            while hasattr(t, '_type_'):
                t = t._type_

            if hasattr(t, 'to_r2'):
                result.append(t.to_r2())
                name = '({}){}'.format(t.__name__, name)
                t = '?'

            fmt += {
                'i': 'd',
                'I': 'x',
                'h': 'w',
                'H': 'w',
                'Q': 'q',
                'L': 'q',
            }.get(t, t)
            names.append(name)
            formats.append(fmt)
        result.append('pf.{} {} {}'.format(cls.__name__, ''.join(formats), ' '.join(names)))
        return '\n'.join(result)

    def check(self):
        if not self.valid:
            raise AssertionError("expected: {}, {} got {}, {}".format(
                self.expected_magic1,
                self.expected_magic2,
                self.magic1,
                self.magic2
            ))


class PartitionHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('header_checksum', c_uint),
        ('data_checksum', c_uint),
        ('hmac', c_byte * 0x14),
        ('unknown', c_byte * 0x2c),
        ('hmac_data', c_byte * 0x14),
        ('remaining', c_byte * 2964)
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'_HP_'


class ElementHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('num_elements', c_uint),
        ('unknown1', c_uint),
        ('offset', c_uint),
        ('unknown2', c_uint),
        ('unknown3', c_uint),
        ('unknown4', c_uint),
        ('unknown5', c_uint),
        ('unknown6', c_uint),
        ('unknown7', c_uint),
        ('unknown8', c_uint * 3)
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'_CE_'


class SubPartitionHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('unknown1', c_byte * 0x18),
        ('data_size', c_uint),
        ('unknown2', c_byte * 0x24),
        ('name', c_char * 0x80),
        ('entries', ElementHeader * 0x10),
        ('unknown3', c_byte * 0x34),
        ('pkcs7', c_byte * (0x706 + 0x27f5)),
#        ('unknown4', c_byte * 0x27f5),
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'_CZK'


class ConfigHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('variable_id', c_short),
        ('section_id', c_short),
        ('unknown1', c_uint),
        ('value', c_long),
        # ('unknown2', c_byte * (256 - 32))
        ('unknown2', c_char * (256 - 32))
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'_VE_'


class FileHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('offset', c_ulong),
        ('filesize', c_ulong),
        ('path_id', c_uint),
        ('filename_id', c_uint),
        ('unknown', c_byte * (256 - 44))
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'_IE_'


class BootHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('offset', c_uint),
        ('unknown', c_byte * (0x1000 - 0x18))
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'BCWZ'


class PartitionTableHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('num_sectors', c_uint),
        ('unknown1', c_uint),
        ('num_elements', c_uint),
        ('unknown2', c_byte * (0x200 - 0x10 - 0xc))
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'RHDP'


class PartitionTableInfoHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('unknown1', c_uint),
        ('partition_type', c_uint),
        ('unknown2', c_uint * 3),
        ('unknown3', c_uint),
        ('unknown4', c_uint * 2),
        ('unknown5', c_uint),
        ('unknown6', c_uint),
        ('unknown7', c_byte * (0x200 - 0x38))
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'YEDP'


class PartitionTableEntryHeader(HeaderMixin, Structure):
    _fields_ = HeaderMixin._fields_ + [
        ('offset', c_uint),
        ('unknown1', c_uint),
        ('entry_size', c_uint),
        ('unknown2', c_uint),
        ('unknown', c_byte * (0x40 - 0x20))
    ]
    expected_magic1 = b'_CP_'
    expected_magic2 = b'EEDP'


class StringEntry(Structure):
    _fields_ = [
        ('length', c_ulong),
        ('offset', c_ulong),
    ]
