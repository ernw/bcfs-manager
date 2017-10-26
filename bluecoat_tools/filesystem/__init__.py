from ctypes import *
import pathlib
import json
import hashlib
from binascii import crc32
import subprocess
import mmap
import hmac
import os

from .pkcs7 import PKCS7
from .native import (
    StringEntry, ConfigHeader, FileHeader, PartitionHeader, SubPartitionHeader,
    BootHeader, PartitionTableHeader, PartitionTableInfoHeader, PartitionTableEntryHeader
)
from .patch import replace_certs, sign_hash, update_checksums


__all__ = (
    'load_filesystems',
    'replace_certs',
    'sign_hash'
)


HMAC_KEY = bytes.fromhex((
    '7b552f02 0a67ca12 8f4a810f 3d40b92f' +
    'cae88dc3 3c5da5ea ca0a80dc 372a17c6' +
    'bb087c33 2cbbb8d2 f4b9e5ac ab4bfa40' +
    'bc67f3fb 6628b610 598006b8 c4e67fbe').replace(' ', ''))


class FileView:
    def __init__(self, f, offset, length):
        self.f = f
        self.f_offset = offset
        self.offset = 0
        self.length = length

    def seek(self, offset, whence=0):
        if whence == os.SEEK_SET:
            self.offset = offset
        elif whence == os.SEEK_CUR:
            self.offset += offset
        elif whence == os.SEEK_END:
            self.offset = self.length + offset
        else:
            # Other values of whence should raise an IOError
            return self.f.seek(offset, whence)
        return self.f.seek(self.offset + self.f_offset, os.SEEK_SET)

    def tell(self):
        return self.offset

    def read(self, size=-1):
        self.seek(self.offset)
        if size<0:
            size = self.length-self.offset
        size = max(0, min(size, self.length-self.offset))
        self.offset += size
        return self.f.read(size)

    def write(self, data):
        self.seek(self.offset)

        size = len(data)
        size = max(0, min(size, self.length - self.offset))
        self.offset += size
        return self.f.write(data[:size])

    def flush(self):
        return self.f.flush()


class Table:
    def __init__(self, entry_class, start_offset, num_entries):
        self.start_offset = start_offset
        self.entry_class = entry_class
        self.entries = []
        self.num_entries = num_entries

    def load(self, fp):
        fp.seek(self.start_offset)
        self.entries = []
        for _ in range(self.num_entries):
            se = self.entry_class()
            fp.readinto(se)
            self.entries.append(se)

    def write(self, fp):
        fp.seek(self.start_offset)
        for e in self.entries:
            fp.write(e)


class StringTable(Table):
    def __init__(self, start_offset, num_entries):
        super().__init__(StringEntry, start_offset, num_entries)
        self.strings = []

    def load(self, fp):
        self.strings = []
        super().load(fp)
        for se in self.entries:
            fp.seek(self.start_offset + se.offset)
            self.strings.append(fp.read(se.length))


class ConfigTable(Table):
    def __init__(self, start_offset, num_entries):
        super().__init__(ConfigHeader, start_offset, num_entries)
        self.configs = {}

    def load(self, fp):
        self.configs = {}
        super().load(fp)

        with (pathlib.Path(__file__).parent / 'section_variables.json').open() as x:
            namemap = json.load(x)

        for entry in self.entries:
            for x in namemap:
                if x['id'] == entry.section_id:
                    section_name = x['name']
                    variables = x['variables']
                    break

            for var in variables:
                if var['id'] == entry.variable_id:
                    variable_name = var['name']
                    break

            self.configs.setdefault(section_name, {})
            self.configs[section_name][variable_name] = entry
            # self.configs[section_name][variable_name] = (entry.unknown1, entry.value, entry.unknown2)
            # self.configs[section_name][variable_name] = entry.value


class FileTable(Table):
    def __init__(self, strings, start_offset, num_entries):
        super().__init__(FileHeader, start_offset, num_entries)
        self._strings = strings
        self.files = {}

    def load(self, fp):
        self.files = {}
        super().load(fp)

        for entry in self.entries:
            idx = entry.path_id >> 4
            if idx > len(self._strings):
                path = '/bug/{}'.format(idx)
            else:
                path = self._strings[idx].decode('utf8')
            # filename = self._strings[entry.filename_id]
            # self.files[path + "/" + filename] = entry
            self.files[path] = entry


class FileSystem:
    def __init__(self, fp, read_only=False):
        self.fp = fp
        self._st = None
        self._ct = None
        self._ft = None
        self._header_checksum = None
        self._data_checksum = None
        self._header_hmac = None
        self._data_hmac = None
        self.signature = None
        self.read_only = read_only

    def get_partitions(self):
        pos = self.fp.tell()
        bh = BootHeader()
        self.fp.readinto(bh)
        if not bh.valid:
            self.fp.seek(pos + 0x1000)
            self.fp.readinto(bh)
            bh.global_offset = pos + 0x1000
            if not bh.valid:
                raise ValueError("Boot header not found at {:x}".format(pos + 0x1000))
        return self.read_part_table(bh.offset)

    def read_part_table(self, start_offset):
        fp = self.fp
        fp.seek(start_offset)
        pth = PartitionTableHeader()
        fp.readinto(pth)
        if not pth.valid:
            raise ValueError("Partition table not found {:x}".format(start_offset))

        partitions = []
        off = start_offset + pth.size
        for _ in range(pth.num_elements):
            fp.seek(off)
            ptih = PartitionTableInfoHeader()
            fp.readinto(ptih)
            ptih.global_offset = off
            ptih.check()
            part = {
                'offset': off,
                'type': ptih.partition_type,
                'subparts': [],
                'magic1': ptih.magic1,
                'magic2': ptih.magic2,
                'unknowns': [
                    ptih.unknown1,
                    ptih.unknown2,
                    ptih.unknown3,
                    ptih.unknown4,
                    ptih.unknown5,
                    ptih.unknown6,
                    ptih.unknown7,
                ],
            }
            partitions.append(part)
            for _ in range((pth.num_sectors - ptih.size) // 0x40):
                pte = PartitionTableEntryHeader()
                fp.readinto(pte)
                entry = {
                    'offset': start_offset + pte.offset,
                    'size': pte.entry_size,
                    'unknowns': [pte.unknown1, pte.unknown2],
                    'subentries': []
                }
                if pte.offset != 0: # and pte.entry_size != 0:
                    x = fp.tell()
                    try:
                        subentries = self.read_part_table(entry['offset'])
                        entry['subentries'] = subentries
                    except ValueError:
                        pass
                    fp.seek(entry['offset'])
                    entry['magic1'] = fp.read(4)
                    fp.seek(entry['offset'] + 12)
                    entry['magic2'] = fp.read(4)
                    fp.seek(x)
                    part['subparts'].append(entry)
            off += pth.num_sectors
        return partitions

    def read_string_and_config_table(self, offset=0):
        fp = self.fp
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        fp.seek(offset)
        fp.readinto(ph)
        fp.readinto(sph)

        if not ph.valid or not sph.valid:
            return False

        self._header_checksum = ph.header_checksum
        self._data_checksum = ph.data_checksum
        self._header_hmac = bytes(ph.hmac)
        self._data_hmac = bytes(ph.hmac_data)

        self._st = StringTable(offset + sph.entries[0].offset, sph.entries[0].num_elements)
        self._st.load(fp)

        self._ct = ConfigTable(offset + sph.entries[1].offset, sph.entries[1].num_elements)
        self._ct.load(fp)

        self._ft = FileTable(self._st.strings, offset + sph.entries[2].offset, sph.entries[2].num_elements)
        self._ft.load(fp)

        self.signature = PKCS7.parse(bytes(sph.pkcs7))

        return True

    def open(self, filename):
        if not self._ft:
            self.read_string_and_config_table()

        if filename not in self._ft.files:
            raise IOError("File {} not found".format(filename))
        e = self._ft.files[filename]
        
        length = e.filesize
        offset = e.offset + self._ft.start_offset

        return FileView(self.fp, offset, length)
        # return mmap.mmap(self.fp.fileno(), length, access=(mmap.ACCESS_READ | mmap.ACCESS_WRITE), offset=offset)

    @property
    def strings(self):
        if not self._st:
            self.read_string_and_config_table()
        return self._st.strings

    @property
    def configs(self):
        if not self._ct:
            self.read_string_and_config_table()
        return self._ct.configs

    @property
    def files(self):
        if not self._ft:
            self.read_string_and_config_table()
        return self._ft.files

    @property
    def header_checksum(self):
        if not self._header_checksum:
            self.read_string_and_config_table()
        return self._header_checksum

    @property
    def data_checksum(self):
        if not self._data_checksum:
            self.read_string_and_config_table()
        return self._data_checksum

    @property
    def hmac(self):
        if not self._header_hmac:
            self.read_string_and_config_table()
        return self._header_hmac

    @property
    def hmac_data(self):
        if not self._data_hmac:
            self.read_string_and_config_table()
        return self._data_hmac

    def save_config(self, section, variable, value):
        e = self.configs[section][variable]
        e.value = int(value)
        self._ct.write(self.fp)
        self.fp.flush()

    def calc_header_checksum(self, offset=0):
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        self.fp.seek(offset)
        self.fp.readinto(ph)
        ph.check()

        start = self.fp.tell()
        self.fp.readinto(sph)
        sph.check()

        self.fp.seek(start)

        data = self.fp.read(offset + sph.entries[0].offset - start)

        return crc32(data)

    def calc_data_checksum(self, offset=0):
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        self.fp.seek(offset)
        self.fp.readinto(ph)
        ph.check()
        self.fp.readinto(sph)
        sph.check()
        self.fp.seek(offset + sph.entries[0].offset)

        data = self.fp.read()

        return crc32(data)

    def calc_sha256(self, offset=0):
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        self.fp.seek(offset)
        self.fp.readinto(ph)
        ph.check()
        self.fp.readinto(sph)

        sph.check()

        off1 = offset + sph.entries[0].offset
        off2 = offset + sizeof(ph)
        len2 = addressof(sph.pkcs7) - addressof(sph)

        self.fp.seek(off1)

        sha256 = hashlib.sha256()

        data = b''
        amount = 0
        for chunk in iter(lambda: self.fp.read(sha256.block_size), b''):
            if len(chunk) < sha256.block_size:
                data = chunk
            else:
                amount += len(chunk)
                sha256.update(chunk)

        self.fp.seek(off2)
        data += self.fp.read(len2)
        amount += len(data)
        sha256.update(data)

        return sha256.hexdigest()

    def calc_hmac_data(self, offset=0):
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        self.fp.seek(offset)
        self.fp.readinto(ph)
        ph.check()
        self.fp.readinto(sph)
        sph.check()

        self.fp.seek(offset + sph.entries[0].offset)
        data = self.fp.read(sph.data_size)
        hm = hmac.HMAC(HMAC_KEY, data, digestmod=hashlib.sha1)
        
        return hm.hexdigest()

    def calc_hmac(self, offset=0):
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        self.fp.seek(offset)
        self.fp.readinto(ph)
        ph.check()

        start = self.fp.tell()
        self.fp.readinto(sph)
        sph.check()

        self.fp.seek(start)

        data = self.fp.read(offset + sph.entries[0].offset - start)
        hm = hmac.HMAC(HMAC_KEY, data, digestmod=hashlib.sha1)

        return hm.hexdigest()

    def get_signature_checksum(self):
        pem = self.signature.get_pem()
        result = subprocess.check_output(['openssl', 'pkcs7', '-inform', 'pem', '-noout', '-print'], input=pem.encode())

        data = []
        state = 0
        for line in result.split(b'\n'):
            if state == 0 and b'object: messageDigest (1.2.840.113549.1.9.4)' in line:
                state = 1
            elif state == 1 and b'OCTET STRING:' in line:
                state = 2
            elif state == 2:
                line = line.strip()
                if line == b'':
                    break
                line = line.split(b' - ', 1)[1]
                line = line.split(b'   ', 1)[0]
                line = line.strip().replace(b'-', b' ')
                data += list(map(lambda x: int(x, 16), line.split(b' ')))

        return bytes(data).hex()

    def set_signature(self, pkcs7, offset=0):
        self.signature = pkcs7
        signature = pkcs7.get_der()

        fp = self.fp
        ph = PartitionHeader()
        sph = SubPartitionHeader()
        fp.seek(offset)
        fp.readinto(ph)
        ph.check()

        off = offset + sizeof(ph)
        fp.readinto(sph)
        sph.check()

        pkcs7off = addressof(sph.pkcs7) - addressof(sph)
        fp.seek(off + pkcs7off)
        fp.write(signature)
        fp.flush()

    def set_checksums(self, headerchk, datachk, hm, hm_data, offset=0):
        fp = self.fp
        ph = PartitionHeader()
        fp.seek(offset)
        fp.readinto(ph)
        ph.check()

        ph.header_checksum = headerchk
        ph.data_checksum = datachk

        fp.seek(offset)
        fp.write(ph)
        fp.flush()

        hmoff = addressof(ph.hmac) - addressof(ph)
        fp.seek(offset + hmoff)
        fp.write(hm)
        fp.flush()

        hmoff = addressof(ph.hmac_data) - addressof(ph)
        fp.seek(offset + hmoff)
        fp.write(hm_data)
        fp.flush()


def load_filesystems(path):
    if not isinstance(path, pathlib.Path):
        path = pathlib.Path(path)

    bootimage = path / "sgos/boot/cmpnts/starter.si"
    systemimage = path / "sgos/boot/systems/system1"

    filesystems = [None, None]
    if bootimage.exists():
        try:
            filesystems[0] = FileSystem(bootimage.open('r+b'))
        except PermissionError:
            filesystems[0] = FileSystem(bootimage.open('rb'), True)
    if systemimage.exists():
        try:
            filesystems[1] = FileSystem(systemimage.open('r+b'))
        except PermissionError:
            filesystems[1] = FileSystem(systemimage.open('rb'), True)

    return filesystems

