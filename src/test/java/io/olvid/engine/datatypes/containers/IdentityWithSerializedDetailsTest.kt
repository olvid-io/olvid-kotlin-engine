/*
 *  Olvid Kotlin Engine
 *  Copyright © 2019-2026 Olvid SAS
 *
 *  This file is part of the Olvid Kotlin Engine.
 *
 *  The Olvid Kotlin Engine is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  The Olvid Kotlin Engine is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with the Olvid Kotlin Engine.  If not, see <https://www.gnu.org/licenses/>.
 */

package io.olvid.engine.datatypes.containers

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class IdentityWithSerializedDetailsTest {

    private lateinit var identity1: Identity
    private lateinit var identity2: Identity

    @Before
    fun setup() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair1 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair1 = EncryptionEciesCurve25519KeyPair.generate(prng)
        identity1 = Identity(
            "alpha.olvid.io",
            serverAuthKeyPair1.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair1.publicKey as EncryptionPublicKey
        )

        val serverAuthKeyPair2 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair2 = EncryptionEciesCurve25519KeyPair.generate(prng)
        identity2 = Identity(
            "beta.olvid.io",
            serverAuthKeyPair2.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair2.publicKey as EncryptionPublicKey
        )
    }

    // ─── Constructor / field access ────────────────────────────────────────────

    @Test
    fun testConstructorStoresFields() {
        val details = """{"firstName":"Alice","lastName":"Smith"}"""
        val obj = IdentityWithSerializedDetails(identity1, details)

        assertEquals(identity1, obj.identity)
        assertEquals(details, obj.serializedDetails)
    }

    @Test
    fun testConstructorAllowsEmptyDetails() {
        val obj = IdentityWithSerializedDetails(identity1, "")
        assertEquals("", obj.serializedDetails)
    }

    // ─── equals / hashCode ─────────────────────────────────────────────────────

    @Test
    fun testEqualsAndHashCodeSameIdentity() {
        val a = IdentityWithSerializedDetails(identity1, """{"name":"Alice"}""")
        val b = IdentityWithSerializedDetails(identity1, """{"name":"Bob"}""")

        // equals is based solely on identity, not serializedDetails
        assertTrue(a == b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun testEqualsReturnsFalseForDifferentIdentity() {
        val a = IdentityWithSerializedDetails(identity1, "details")
        val b = IdentityWithSerializedDetails(identity2, "details")

        assertFalse(a == b)
    }

    @Test
    fun testEqualsReturnsFalseForNonInstance() {
        val a = IdentityWithSerializedDetails(identity1, "details")

        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals("not-an-identity-with-details"))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals(null))
    }

    @Test
    fun testEqualsSameReference() {
        val a = IdentityWithSerializedDetails(identity1, "details")

        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(a.equals(a))
    }

    @Test
    fun testHashCodeDelegatesToIdentity() {
        val obj = IdentityWithSerializedDetails(identity1, "details")
        assertEquals(identity1.hashCode(), obj.hashCode())
    }

    // ─── compareTo ─────────────────────────────────────────────────────────────

    @Test
    fun testCompareToEqualIdentities() {
        val a = IdentityWithSerializedDetails(identity1, "a-details")
        val b = IdentityWithSerializedDetails(identity1, "b-details")

        assertEquals(0, a.compareTo(b))
    }

    @Test
    fun testCompareToDistinctIdentities() {
        val a = IdentityWithSerializedDetails(identity1, "details")
        val b = IdentityWithSerializedDetails(identity2, "details")

        val cmpAB = a.compareTo(b)
        val cmpBA = b.compareTo(a)

        // Must have opposite signs
        assertTrue(cmpAB != 0)
        assertTrue((cmpAB < 0) xor (cmpBA < 0))
    }

    @Test
    fun testCompareToIsConsistentWithEquals() {
        val a = IdentityWithSerializedDetails(identity1, "x")
        val b = IdentityWithSerializedDetails(identity1, "y")

        // compareTo == 0 <=> equals
        assertEquals(0, a.compareTo(b))
        assertTrue(a == b)
    }

    // ─── encode / decode (round-trip) ──────────────────────────────────────────

    @Test
    fun testEncodeDecodeSingleRoundTrip() {
        val details = """{"firstName":"Carol","lastName":"Jones"}"""
        val original = IdentityWithSerializedDetails(identity1, details)

        val encoded: Encoded = original.encode()
        val decoded = IdentityWithSerializedDetails.of(encoded)

        assertEquals(original.identity, decoded.identity)
        assertEquals(original.serializedDetails, decoded.serializedDetails)
    }

    @Test
    fun testEncodeDecodeWithEmptyDetails() {
        val original = IdentityWithSerializedDetails(identity2, "")
        val decoded = IdentityWithSerializedDetails.of(original.encode())

        assertEquals(original.identity, decoded.identity)
        assertEquals("", decoded.serializedDetails)
    }

    @Test
    fun testEncodeDecodeWithSpecialCharacterDetails() {
        val details = "\"emoji\":\"\\uD83D\\uDE00\",\"newline\":\"line1\\nline2\""
        val original = IdentityWithSerializedDetails(identity1, details)
        val decoded = IdentityWithSerializedDetails.of(original.encode())

        assertEquals(details, decoded.serializedDetails)
    }

    @Test
    fun testEncodeProducesNonNullEncoded() {
        val obj = IdentityWithSerializedDetails(identity1, "test")
        val encoded = obj.encode()
        assertNotNull(encoded)
        assertNotNull(encoded.bytes)
        assertTrue(encoded.bytes.isNotEmpty())
    }

    @Test
    fun testDecodeInvalidLengthThrowsDecodingException() {
        // An Encoded list with only one element must throw DecodingException
        val shortEncoded = Encoded.of(arrayOf(Encoded.of(identity1)))
        try {
            IdentityWithSerializedDetails.of(shortEncoded)
            fail("Expected DecodingException for list length != 2")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeEmptyListThrowsDecodingException() {
        val emptyEncoded = Encoded.of(arrayOf<Encoded>())
        try {
            IdentityWithSerializedDetails.of(emptyEncoded)
            fail("Expected DecodingException for empty list")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeTooManyElementsThrowsDecodingException() {
        // A list with 3 elements must throw DecodingException
        val tooLong = Encoded.of(arrayOf(
            Encoded.of(identity1),
            Encoded.of("some details"),
            Encoded.of("extra element")
        ))
        try {
            IdentityWithSerializedDetails.of(tooLong)
            fail("Expected DecodingException for list length != 2")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // ─── encode bytes are stable across two calls ───────────────────────────────

    @Test
    fun testEncodeBytesAreDeterministic() {
        val obj = IdentityWithSerializedDetails(identity1, "stable-details")
        assertArrayEquals(obj.encode().bytes, obj.encode().bytes)
    }
}
