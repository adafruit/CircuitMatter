#! /usr/bin/env python

# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT
#
# Derived from https://github.com/tlsfuzzer/python-ecdsa

"""
Low level implementation of Elliptic-Curve Digital Signatures.

.. note ::
    You're most likely looking for the :py:class:`~ecdsa.keys` module.
    This is a low-level implementation of the ECDSA that operates on
    integers, not byte strings.

NOTE: This a low level implementation of ECDSA, for normal applications
you should be looking at the keys.py module.

Classes and methods for elliptic-curve signatures:
private keys, public keys, signatures,
and definitions of prime-modulus curves.

Example:

.. code-block:: python

   # (In real-life applications, you would probably want to
   # protect against defects in SystemRandom.)
   from random import SystemRandom
   randrange = SystemRandom().randrange

   # Generate a public/private key pair using the NIST Curve P-192:

   g = generator_192
   n = g.order()
   secret = randrange( 1, n )
   pubkey = Public_key( g, g * secret )
   privkey = Private_key( pubkey, secret )

   # Signing a hash value:

   hash = randrange( 1, n )
   signature = privkey.sign( hash, randrange( 1, n ) )

   # Verifying a signature for a hash value:

   if pubkey.verifies( hash, signature ):
     print("Demo verification succeeded.")
   else:
     print("*** Demo verification failed.")

   # Verification fails if the hash value is modified:

   if pubkey.verifies( hash-1, signature ):
     print("**** Demo verification failed to reject tampered hash.")
   else:
     print("Demo verification correctly rejected tampered hash.")

Revision history:
      2005.12.31 - Initial version.

      2008.11.25 - Substantial revisions introducing new classes.

      2009.05.16 - Warn against using random.randrange in real applications.

      2009.05.17 - Use random.SystemRandom by default.

Originally written in 2005 by Peter Pearson and placed in the public domain,
modified as part of the python-ecdsa package.
"""

from . import ellipticcurve, numbertheory
from ._compat import int2byte


class RSZeroError(RuntimeError):
    pass


class InvalidPointError(RuntimeError):
    pass


class Signature:
    """
    ECDSA signature.

    :ivar int r: the ``r`` element of the ECDSA signature
    :ivar int s: the ``s`` element of the ECDSA signature
    """

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def recover_public_keys(self, hash, generator):
        """
        Returns two public keys for which the signature is valid

        :param int hash: signed hash
        :param AbstractPoint generator: is the generator used in creation
            of the signature
        :rtype: tuple(Public_key, Public_key)
        :return: a pair of public keys that can validate the signature
        """
        curve = generator.curve()
        n = generator.order()
        r = self.r
        s = self.s
        e = hash
        x = r

        # Compute the curve point with x as x-coordinate
        alpha = (pow(x, 3, curve.p()) + (curve.a() * x) + curve.b()) % curve.p()
        beta = numbertheory.square_root_mod_prime(alpha, curve.p())
        y = beta if beta % 2 == 0 else curve.p() - beta

        # Compute the public key
        R1 = ellipticcurve.PointJacobi(curve, x, y, 1, n)
        Q1 = numbertheory.inverse_mod(r, n) * (s * R1 + (-e % n) * generator)
        Pk1 = Public_key(generator, Q1)

        # And the second solution
        R2 = ellipticcurve.PointJacobi(curve, x, -y, 1, n)
        Q2 = numbertheory.inverse_mod(r, n) * (s * R2 + (-e % n) * generator)
        Pk2 = Public_key(generator, Q2)

        return [Pk1, Pk2]


class Public_key:
    """Public key for ECDSA."""

    def __init__(self, generator, point, verify=True):
        """Low level ECDSA public key object.

        :param generator: the Point that generates the group (the base point)
        :param point: the Point that defines the public key
        :param bool verify: if True check if point is valid point on curve

        :raises InvalidPointError: if the point parameters are invalid or
            point does not lay on the curve
        """

        self.curve = generator.curve()
        self.generator = generator
        self.point = point
        n = generator.order()
        p = self.curve.p()
        if not (0 <= point.x() < p) or not (0 <= point.y() < p):
            raise InvalidPointError("The public point has x or y out of range.")
        if verify and not self.curve.contains_point(point.x(), point.y()):
            raise InvalidPointError("Point does not lay on the curve")
        if not n:
            raise InvalidPointError("Generator point must have order.")
        # for curve parameters with base point with cofactor 1, all points
        # that are on the curve are scalar multiples of the base point, so
        # verifying that is not necessary. See Section 3.2.2.1 of SEC 1 v2
        if verify and self.curve.cofactor() != 1 and not n * point == ellipticcurve.INFINITY:
            raise InvalidPointError("Generator point order is bad.")

    def __eq__(self, other):
        """Return True if the keys are identical, False otherwise.

        Note: for comparison, only placement on the same curve and point
        equality is considered, use of the same generator point is not
        considered.
        """
        if isinstance(other, Public_key):
            return self.curve == other.curve and self.point == other.point
        return NotImplemented

    def __ne__(self, other):
        """Return False if the keys are identical, True otherwise."""
        return not self == other

    def verifies(self, hash, signature):
        """Verify that signature is a valid signature of hash.
        Return True if the signature is valid.
        """

        # From X9.62 J.3.1.

        G = self.generator
        n = G.order()
        r = signature.r
        s = signature.s
        if r < 1 or r > n - 1:
            return False
        if s < 1 or s > n - 1:
            return False
        c = numbertheory.inverse_mod(s, n)
        u1 = (hash * c) % n
        u2 = (r * c) % n
        if hasattr(G, "mul_add"):
            xy = G.mul_add(u1, self.point, u2)
        else:
            xy = u1 * G + u2 * self.point
        v = xy.x() % n
        return v == r


class Private_key:
    """Private key for ECDSA."""

    def __init__(self, public_key, secret_multiplier):
        """public_key is of class Public_key;
        secret_multiplier is a large integer.
        """

        self.public_key = public_key
        self.secret_multiplier = secret_multiplier

    def __eq__(self, other):
        """Return True if the points are identical, False otherwise."""
        if isinstance(other, Private_key):
            return (
                self.public_key == other.public_key
                and self.secret_multiplier == other.secret_multiplier
            )
        return NotImplemented

    def __ne__(self, other):
        """Return False if the points are identical, True otherwise."""
        return not self == other

    def sign(self, hash, random_k):
        """Return a signature for the provided hash, using the provided
        random nonce.  It is absolutely vital that random_k be an unpredictable
        number in the range [1, self.public_key.point.order()-1].  If
        an attacker can guess random_k, he can compute our private key from a
        single signature.  Also, if an attacker knows a few high-order
        bits (or a few low-order bits) of random_k, he can compute our private
        key from many signatures.  The generation of nonces with adequate
        cryptographic strength is very difficult and far beyond the scope
        of this comment.

        May raise RuntimeError, in which case retrying with a new
        random value k is in order.
        """

        G = self.public_key.generator
        n = G.order()
        k = random_k % n
        # Fix the bit-length of the random nonce,
        # so that it doesn't leak via timing.
        # This does not change that ks = k mod n
        ks = k + n
        kt = ks + n
        if ks.bit_length() == n.bit_length():
            p1 = kt * G
        else:
            p1 = ks * G
        r = p1.x() % n
        if r == 0:
            raise RSZeroError("amazingly unlucky random number r")
        s = (numbertheory.inverse_mod(k, n) * (hash + (self.secret_multiplier * r) % n)) % n
        if s == 0:
            raise RSZeroError("amazingly unlucky random number s")
        return Signature(r, s)


def point_is_valid(generator, x, y):
    """Is (x,y) a valid public key based on the specified generator?"""

    # These are the tests specified in X9.62.

    n = generator.order()
    curve = generator.curve()
    p = curve.p()
    if not (0 <= x < p) or not (0 <= y < p):
        return False
    if not curve.contains_point(x, y):
        return False
    if (
        curve.cofactor() != 1
        and not n * ellipticcurve.PointJacobi(curve, x, y, 1) == ellipticcurve.INFINITY
    ):
        return False
    return True

# NIST Curve P-256:
_p = 1157920892103562487626974469494075735300861434152903141955_33631308867097853951
_r = 115792089210356248762697446949407573529996955224135760342_422259061068512044369
# s = 0xc49d360886e704936a6678e1139d26b7819f7e90L
# c = 0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0dL
_b = 0x5AC635D8_AA3A93E7_B3EBBD55_769886BC_651D06B0_CC53B0F6_3BCE3C3E_27D2604B
_Gx = 0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296
_Gy = 0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5

curve_256 = ellipticcurve.CurveFp(_p, -3, _b, 1)
generator_256 = ellipticcurve.PointJacobi(curve_256, _Gx, _Gy, 1, _r, generator=True)
