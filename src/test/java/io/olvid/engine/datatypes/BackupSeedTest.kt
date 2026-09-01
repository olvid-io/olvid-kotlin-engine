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

package io.olvid.engine.datatypes

import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger

class BackupSeedTest {

    @Test
    fun testConstructorAndGettersSuccess() {
        val bytes = ByteArray(20) { it.toByte() }
        val seed = BackupSeed(bytes)
        assertArrayEquals(bytes, seed.backupSeedBytes)
    }

    @Test
    fun testConstructorBadLengthThrows() {
        val shortBytes = ByteArray(19) { 0 }
        try {
            BackupSeed(shortBytes)
            fail("Expected exception for short bytes")
        } catch (e: Exception) {
            assertEquals("Bad backupSeedBytes length", e.message)
        }

        val longBytes = ByteArray(21) { 0 }
        try {
            BackupSeed(longBytes)
            fail("Expected exception for long bytes")
        } catch (e: Exception) {
            assertEquals("Bad backupSeedBytes length", e.message)
        }
    }

    @Test
    fun testGenerateSuccess() {
        val prng = Suite.getDefaultPRNGService(0)
        val seed = BackupSeed.generate(prng)
        assertNotNull(seed)
        assertEquals(20, seed!!.backupSeedBytes.size)
    }

    @Test
    fun testGenerateFailure() {
        val throwingPrng = object : PRNG {
            override fun bytes(l: Int): ByteArray {
                throw Exception("Mock PRNG error")
            }
            override fun bigInt(n: BigInteger): BigInteger {
                throw Exception("Mock PRNG error")
            }
        }
        val seed = BackupSeed.generate(throwingPrng)
        assertNull(seed)
    }

    @Test
    fun testStringConstructorSuccessAndToString() {
        // Generate a random seed
        val prng = Suite.getDefaultPRNGService(0)
        val originalSeed = BackupSeed.generate(prng)
        assertNotNull(originalSeed)

        val seedString = originalSeed!!.toString()
        // Format of seedString is "XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX" (39 characters: 8 groups of 4 separated by 7 spaces)
        assertEquals(39, seedString.length)
        for (i in 0 until 39) {
            if (i % 5 == 4) {
                assertEquals(' ', seedString[i])
            } else {
                assertNotEquals(' ', seedString[i])
            }
        }

        // Reconstruct from string
        val reconstructedSeed = BackupSeed(seedString)
        assertEquals(originalSeed, reconstructedSeed)
        assertEquals(seedString, reconstructedSeed.toString())
    }

    @Test
    fun testStringConstructorTooShort() {
        // String has only 31 chars instead of 32 decodable chars
        val shortString = "0123 4567 89AB CDEF GHJK LMNP QRTU VWX"
        try {
            BackupSeed(shortString)
            fail("Expected SeedTooShortException")
        } catch (_: BackupSeed.SeedTooShortException) {
            // Expected
        }
    }

    @Test
    fun testStringConstructorTooLong() {
        // String has 33 decodable chars
        val longString = "0123 4567 89AB CDEF GHJK LMNP QRTU VWXY Z"
        try {
            BackupSeed(longString)
            fail("Expected SeedTooLongException")
        } catch (_: BackupSeed.SeedTooLongException) {
            // Expected
        }
    }

    @Test
    fun testStringConstructorIgnoresInvalidAndBounds() {
        // Valid string: "0123456789ABCDEFGHJKLMNPQRTUVWXY" (32 chars)
        // Let's add some ignored chars (e.g. lowercase letter 'z', punctuation, and spaces)
        val validString = "0123456789ABCDEFGHJKLMNPQRTUVWXY"
        val seed1 = BackupSeed(validString)

        val noisyString = "0123456789ABCDEF*GHJKLMNP-QRTUVWXY"
        val seed2 = BackupSeed(noisyString)
        assertEquals(seed1, seed2)

        // Char code out of bounds: unicode character above 255
        val outOfBoundsString = "0123456789ABCDEF\u0100GHJKLMNPQRTUVWXY"
        val seed3 = BackupSeed(outOfBoundsString)
        assertEquals(seed1, seed3)
    }

    @Test
    fun testEqualsAndHashCode() {
        val bytes1 = ByteArray(20) { 1.toByte() }
        val bytes2 = ByteArray(20) { 1.toByte() }
        val bytes3 = ByteArray(20) { 2.toByte() }

        val seed1 = BackupSeed(bytes1)
        val seed2 = BackupSeed(bytes2)
        val seed3 = BackupSeed(bytes3)

        // Reflexive
        assertEquals(seed1, seed1)

        // Symmetric
        assertEquals(seed1, seed2)
        assertEquals(seed2, seed1)

        // Different content
        assertNotEquals(seed1, seed3)

        // Different types
        assertNotEquals(seed1, "not a seed")

        // Null
        assertNotEquals(seed1, null)

        // HashCode
        assertEquals(seed1.hashCode(), seed2.hashCode())
        assertNotEquals(seed1.hashCode(), seed3.hashCode())
    }

    @Test
    fun testDeriveKeysAndV2() {
        val bytes = ByteArray(20) { it.toByte() }
        val seed = BackupSeed(bytes)

        // Derive keys V1
        val derived = seed.deriveKeys()
        assertNotNull(derived)
        assertNotNull(derived.backupKeyUid)
        assertNotNull(derived.encryptionKeyPair)
        assertNotNull(derived.macKey)

        // Derive keys V2
        val derivedV2 = seed.deriveKeysV2()
        assertNotNull(derivedV2)
        assertNotNull(derivedV2.backupKeyUid)
        assertNotNull(derivedV2.encryptionKey)
        assertNotNull(derivedV2.authenticationKeyPair)
    }

    @Test
    fun testStaticDelegatorReflection() {
        val prng = Suite.getDefaultPRNGService(0)
        // Get static method on outer class BackupSeed
        val method = BackupSeed::class.java.getMethod("generate", PRNG::class.java)
        val seed = method.invoke(null, prng) as? BackupSeed
        assertNotNull(seed)
        assertEquals(20, seed!!.backupSeedBytes.size)
    }
}
