import hmac
from hashlib import sha256, sha1
from binascii import crc32
from pathlib import Path
import logging
import struct
import subprocess

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from .pkcs7 import PKCS7


log = logging.getLogger(__name__)

CA_CERT = Path(__file__).parent / 'new_ca.pem'
CA_KEY = Path(__file__).parent / 'new_ca.key'
ROOT_CA_CERT = Path(__file__).parent / 'new_root_ca.pem'
ROOT_CA_KEY = Path(__file__).parent / 'new_root_ca.key'
SIGNER_CERT = Path(__file__).parent / 'signer.pem'
SIGNER_KEY = Path(__file__).parent / 'signer.key'

ROOT_CA_RELOC_ID = 343
ROOT_CA_LEN_RELOC_ID = 355
CA_RELOC_ID = 350
CA_LEN_RELOC_ID = 348


def virtual_to_physical(elf, voff):
    for section in elf.iter_sections():
        start = section['sh_addr']
        end = start + section['sh_size']

        if start <= voff <= end:
            return section['sh_offset'] + (voff - start)


def replace_certs(starter_exe):
    with CA_CERT.open('rb') as fp:
        ca_cert = load_pem_x509_certificate(fp.read(), backend)
        ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
    
    elf = ELFFile(starter_exe)

    relocation = elf.get_section_by_name('.rel.dyn')

    assert isinstance(relocation, RelocationSection)

    voffset = relocation.get_relocation(CA_LEN_RELOC_ID)['r_offset']
    poffset = virtual_to_physical(elf, voffset)

    starter_exe.seek(poffset)
    voffset = struct.unpack('<I', starter_exe.read(4))[0]
    poffset = virtual_to_physical(elf, voffset)

    starter_exe.seek(poffset)
    orig_len = struct.unpack('<I', starter_exe.read(4))[0]

    assert orig_len == len(ca_cert_der)


    voffset = relocation.get_relocation(CA_RELOC_ID)['r_offset']
    poffset = virtual_to_physical(elf, voffset)

    starter_exe.seek(poffset)
    voffset = struct.unpack('<I', starter_exe.read(4))[0]
    poffset = virtual_to_physical(elf, voffset)
    
    starter_exe.seek(poffset)
    orig_ca = starter_exe.read(orig_len)
    
    starter_exe.seek(poffset)
    starter_exe.write(ca_cert_der)


def sign_hash(hash, system_fs):
    log.debug("Signing hash %s", hash.hex())

    cmd = [
        'openssl',
        'smime',
        '-signer', str(SIGNER_CERT),
        '-inkey', str(SIGNER_KEY),
        '-pk7out',
        '-binary',
        '-sign',
        '-md', 'sha512',
        '-outform', 'der'
    ]
    log.debug('Running %r', cmd)

    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    p.stdin.write(hash)
    p.stdin.flush()
    p.stdin.close()

    p7 = p.stdout.read()
    p.wait()

    pkcs7 = PKCS7.parse(p7)

    system_fs.set_signature(pkcs7)

    return

    lib = backend._lib
    ffi = backend._ffi

    with SIGNER_CERT.open('rb') as fp:
        signer_cert = load_pem_x509_certificate(fp.read(), backend)

    with SIGNER_KEY.open('rb') as fp:
        signer_key = serialization.load_pem_private_key(fp.read(), None, backend)

    hash_bio = backend._bytes_to_bio(hash)
    p7 = lib.PKCS7_sign(signer_cert._x509, signer_key._evp_pkey, ffi.NULL, hash_bio.bio, lib.PKCS7_DETACHED | lib.PKCS7_BINARY)

    pkcs7 = PKCS7(backend, p7)

    system_fs.set_signature(pkcs7)


def update_checksums(fs):
    headerchk = fs.calc_header_checksum()
    datachk = fs.calc_data_checksum()
    hm = bytes.fromhex(fs.calc_hmac())
    hm_data = bytes.fromhex(fs.calc_hmac_data())

    fs.set_checksums(headerchk, datachk, hm, hm_data)
