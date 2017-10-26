from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.backends.openssl.x509 import _Certificate
import enum
import base64


class PKCS7Type(enum.Enum):
    SIGNED = 0
    ENCRYPTED = 1
    ENVELOPED = 2
    SIGNED_AND_ENVELOPED = 2
    DATA = 4
    DIGEST = 5


class PKCS7:
    def __init__(self, backend, pkcs7):
        self._backend = backend
        self._pkcs7 = pkcs7
        self._signers = None

    @property
    def type(self):
        if self._backend._lib.PKCS7_type_is_encrypted(self._pkcs7):
            return PKCS7Type.ENCRYPTED
        if self._backend._lib.PKCS7_type_is_signed(self._pkcs7):
            return PKCS7Type.SIGNED
        if self._backend._lib.PKCS7_type_is_enveloped(self._pkcs7):
            return PKCS7Type.ENVELOPED
        if self._backend._lib.PKCS7_type_is_signedAndEnveloped(self._pkcs7):
            return PKCS7Type.SIGNED_AND_ENVELOPED
        if self._backend._lib.PKCS7_type_is_data(self._pkcs7):
            return PKCS7Type.DATA
        if self._backend._lib.PKCS7_type_is_digest(self._pkcs7):
            return PKCS7Type.DIGEST

    @property
    def signers(self):
        if self._signers is None:
            x509_stack = self._backend._lib.PKCS7_get0_signers(self._pkcs7, self._backend._ffi.NULL, 0)
            signers = []
            for i in range(self._backend._lib.sk_X509_num(x509_stack)):
                x509 = self._backend._lib.sk_X509_value(x509_stack, i)
                signers.append(_Certificate(self._backend, x509))
            self._signers = signers
        return self._signers

    def __repr__(self):
        return '<PKCS7 type={} digest={} signers={}>'.format(
            self.type.name,
            list(map(lambda s: "/".join(map(lambda a: "{}={}".format(a.oid._name, a.value), s.subject)), self.signers))
        )

    def get_pem(self):
        flags = self._backend._lib.PKCS7_DETACHED
        bio_out = self._backend._create_mem_bio_gc()
        self._backend._lib.SMIME_write_PKCS7(bio_out, self._pkcs7, self._backend._ffi.NULL, flags)
        data = self._backend._read_mem_bio(bio_out)
        return '-----BEGIN PKCS7-----\n' + data.split(b'\n\n', 1)[1].decode().strip() + '\n-----END PKCS7-----'

    def get_der(self):
        flags = self._backend._lib.PKCS7_DETACHED
        bio_out = self._backend._create_mem_bio_gc()
        self._backend._lib.SMIME_write_PKCS7(bio_out, self._pkcs7, self._backend._ffi.NULL, flags)
        data = self._backend._read_mem_bio(bio_out)
        return base64.b64decode(data.split(b'\n\n', 1)[1])

    @classmethod
    def parse(cls, data):
        pkcs7_bio = backend._bytes_to_bio(data)
        pkcs7 = backend._lib.d2i_PKCS7_bio(pkcs7_bio.bio, backend._ffi.NULL)
        if pkcs7 == backend._ffi.NULL:
            backend._consume_errors()
            raise ValueError("Unable to load pkcs7")

        pkcs7 = backend._ffi.gc(pkcs7, backend._lib.PKCS7_free)

        return cls(backend, pkcs7)