# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT
#
# Derived from https://github.com/tlsfuzzer/python-ecdsa

from . import der, ecdsa, ellipticcurve
from .util import orderlen, number_to_string, string_to_number
from ._compat import normalise_bytes


PRIME_FIELD_OID = (1, 2, 840, 10045, 1, 1)
CHARACTERISTIC_TWO_FIELD_OID = (1, 2, 840, 10045, 1, 2)


class UnknownCurveError(Exception):
    pass


class Curve:
    def __init__(self, name, curve, generator, oid, openssl_name=None):
        self.name = name
        self.openssl_name = openssl_name  # maybe None
        self.curve = curve
        self.generator = generator
        self.order = generator.order()
        self.baselen = orderlen(self.order)
        self.verifying_key_length = 2 * orderlen(curve.p())
        self.signature_length = 2 * self.baselen
        self.oid = oid
        if oid:
            self.encoded_oid = der.encode_oid(*oid)

    def __eq__(self, other):
        if isinstance(other, Curve):
            return (
                self.curve == other.curve and self.generator == other.generator
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return self.name

    def to_der(self, encoding=None, point_encoding="uncompressed"):
        """Serialise the curve parameters to binary string.

        :param str encoding: the format to save the curve parameters in.
            Default is ``named_curve``, with fallback being the ``explicit``
            if the OID is not set for the curve.
        :param str point_encoding: the point encoding of the generator when
            explicit curve encoding is used. Ignored for ``named_curve``
            format.

        :return: DER encoded ECParameters structure
        :rtype: bytes
        """
        if encoding is None:
            if self.oid:
                encoding = "named_curve"
            else:
                encoding = "explicit"

        if encoding not in ("named_curve", "explicit"):
            raise ValueError(
                "Only 'named_curve' and 'explicit' encodings supported"
            )

        if encoding == "named_curve":
            if not self.oid:
                raise UnknownCurveError(
                    "Can't encode curve using named_curve encoding without "
                    "associated curve OID"
                )
            return der.encode_oid(*self.oid)

        # encode the ECParameters sequence
        curve_p = self.curve.p()
        version = der.encode_integer(1)
        field_id = der.encode_sequence(
            der.encode_oid(*PRIME_FIELD_OID), der.encode_integer(curve_p)
        )
        curve = der.encode_sequence(
            der.encode_octet_string(
                number_to_string(self.curve.a() % curve_p, curve_p)
            ),
            der.encode_octet_string(
                number_to_string(self.curve.b() % curve_p, curve_p)
            ),
        )
        base = der.encode_octet_string(self.generator.to_bytes(point_encoding))
        order = der.encode_integer(self.generator.order())
        seq_elements = [version, field_id, curve, base, order]
        if self.curve.cofactor():
            cofactor = der.encode_integer(self.curve.cofactor())
            seq_elements.append(cofactor)

        return der.encode_sequence(*seq_elements)

    def to_pem(self, encoding=None, point_encoding="uncompressed"):
        """
        Serialise the curve parameters to the :term:`PEM` format.

        :param str encoding: the format to save the curve parameters in.
            Default is ``named_curve``, with fallback being the ``explicit``
            if the OID is not set for the curve.
        :param str point_encoding: the point encoding of the generator when
            explicit curve encoding is used. Ignored for ``named_curve``
            format.

        :return: PEM encoded ECParameters structure
        :rtype: str
        """
        return der.topem(
            self.to_der(encoding, point_encoding), "EC PARAMETERS"
        )

    @staticmethod
    def from_der(data, valid_encodings=None):
        """Decode the curve parameters from DER file.

        :param data: the binary string to decode the parameters from
        :type data: :term:`bytes-like object`
        :param valid_encodings: set of names of allowed encodings, by default
            all (set by passing ``None``), supported ones are ``named_curve``
            and ``explicit``
        :type valid_encodings: :term:`set-like object`
        """
        if not valid_encodings:
            valid_encodings = set(("named_curve", "explicit"))
        if not all(i in ["named_curve", "explicit"] for i in valid_encodings):
            raise ValueError(
                "Only named_curve and explicit encodings supported"
            )
        data = normalise_bytes(data)
        if not der.is_sequence(data):
            if "named_curve" not in valid_encodings:
                raise der.UnexpectedDER(
                    "named_curve curve parameters not allowed"
                )
            oid, empty = der.remove_object(data)
            if empty:
                raise der.UnexpectedDER("Unexpected data after OID")
            return find_curve(oid)

        if "explicit" not in valid_encodings:
            raise der.UnexpectedDER("explicit curve parameters not allowed")

        seq, empty = der.remove_sequence(data)
        if empty:
            raise der.UnexpectedDER(
                "Unexpected data after ECParameters structure"
            )
        # decode the ECParameters sequence
        version, rest = der.remove_integer(seq)
        if version != 1:
            raise der.UnexpectedDER("Unknown parameter encoding format")
        field_id, rest = der.remove_sequence(rest)
        curve, rest = der.remove_sequence(rest)
        base_bytes, rest = der.remove_octet_string(rest)
        order, rest = der.remove_integer(rest)
        cofactor = None
        if rest:
            # the ASN.1 specification of ECParameters allows for future
            # extensions of the sequence, so ignore the remaining bytes
            cofactor, _ = der.remove_integer(rest)

        # decode the ECParameters.fieldID sequence
        field_type, rest = der.remove_object(field_id)
        if field_type == CHARACTERISTIC_TWO_FIELD_OID:
            raise UnknownCurveError("Characteristic 2 curves unsupported")
        if field_type != PRIME_FIELD_OID:
            raise UnknownCurveError(
                "Unknown field type: {0}".format(field_type)
            )
        prime, empty = der.remove_integer(rest)
        if empty:
            raise der.UnexpectedDER(
                "Unexpected data after ECParameters.fieldID.Prime-p element"
            )

        # decode the ECParameters.curve sequence
        curve_a_bytes, rest = der.remove_octet_string(curve)
        curve_b_bytes, rest = der.remove_octet_string(rest)
        # seed can be defined here, but we don't parse it, so ignore `rest`

        curve_a = string_to_number(curve_a_bytes)
        curve_b = string_to_number(curve_b_bytes)

        curve_fp = ellipticcurve.CurveFp(prime, curve_a, curve_b, cofactor)

        # decode the ECParameters.base point

        base = ellipticcurve.PointJacobi.from_bytes(
            curve_fp,
            base_bytes,
            valid_encodings=("uncompressed", "compressed", "hybrid"),
            order=order,
            generator=True,
        )
        tmp_curve = Curve("unknown", curve_fp, base, None)

        # if the curve matches one of the well-known ones, use the well-known
        # one in preference, as it will have the OID and name associated
        for i in curves:
            if tmp_curve == i:
                return i
        return tmp_curve

    @classmethod
    def from_pem(cls, string, valid_encodings=None):
        """Decode the curve parameters from PEM file.

        :param str string: the text string to decode the parameters from
        :param valid_encodings: set of names of allowed encodings, by default
            all (set by passing ``None``), supported ones are ``named_curve``
            and ``explicit``
        :type valid_encodings: :term:`set-like object`
        """
        if isinstance(string, str):  # pragma: no branch
            string = string.encode()

        ec_param_index = string.find(b"-----BEGIN EC PARAMETERS-----")
        if ec_param_index == -1:
            raise der.UnexpectedDER("EC PARAMETERS PEM header not found")

        return cls.from_der(
            der.unpem(string[ec_param_index:]), valid_encodings
        )


NIST256p = Curve(
    "NIST256p",
    ecdsa.curve_256,
    ecdsa.generator_256,
    (1, 2, 840, 10045, 3, 1, 7),
    "prime256v1",
)

# no order in particular, but keep previously added curves first
curves = [
    NIST256p,
]


def find_curve(oid_curve):
    """Select a curve based on its OID

    :param tuple[int,...] oid_curve: ASN.1 Object Identifier of the
        curve to return, like ``(1, 2, 840, 10045, 3, 1, 7)`` for ``NIST256p``.

    :raises UnknownCurveError: When the oid doesn't match any of the supported
        curves

    :rtype: ~ecdsa.curves.Curve
    """
    for c in curves:
        if c.oid == oid_curve:
            return c
    raise UnknownCurveError(
        "I don't know about the curve with oid %s."
        "I only know about these: %s" % (oid_curve, [c.name for c in curves])
    )


def curve_by_name(name):
    """Select a curve based on its name.

    Returns a :py:class:`~ecdsa.curves.Curve` object with a ``name`` name.
    Note that ``name`` is case-sensitve.

    :param str name: Name of the curve to return, like ``NIST256p`` or
        ``prime256v1``

    :raises UnknownCurveError: When the name doesn't match any of the supported
        curves

    :rtype: ~ecdsa.curves.Curve
    """
    for c in curves:
        if name == c.name or (c.openssl_name and name == c.openssl_name):
            return c
    raise UnknownCurveError(
        "Curve with name {0!r} unknown, only curves supported: {1}".format(
            name, [c.name for c in curves]
        )
    )
