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
import io.olvid.engine.datatypes.key.symmetric.AuthEncAES256ThenSHA256Key
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import org.junit.Assert.*
import org.junit.Test

class SeedTest {

    @Test
    fun testConstructorWithByteArray() {
        val validBytes = ByteArray(32) { it.toByte() }
        val seed = Seed(validBytes)
        assertArrayEquals(validBytes, seed.bytes)
        assertEquals(32, seed.length)

        val tooShortBytes = ByteArray(31) { it.toByte() }
        try {
            Seed(tooShortBytes)
            fail("Expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun testConstructorWithPRNG() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, zeroSeed)
        val seed = Seed(prng)
        assertEquals(32, seed.length)
        assertNotNull(seed.bytes)
    }

    @Test
    fun testConstructorConcatenate() {
        val bytes1 = ByteArray(32) { 1.toByte() }
        val bytes2 = ByteArray(32) { 2.toByte() }
        val seed1 = Seed(bytes1)
        val seed2 = Seed(bytes2)

        val concatenated = Seed(seed1, seed2)
        assertEquals(64, concatenated.length)

        val expected = ByteArray(64)
        System.arraycopy(bytes1, 0, expected, 0, 32)
        System.arraycopy(bytes2, 0, expected, 32, 32)
        assertArrayEquals(expected, concatenated.bytes)
    }

    @Test
    fun testToStringEqualsAndHashCode() {
        val bytes1 = ByteArray(32) { 1.toByte() }
        val bytes2 = ByteArray(32) { 1.toByte() }
        val bytes3 = ByteArray(32) { 3.toByte() }

        val seed1 = Seed(bytes1)
        val seed2 = Seed(bytes2)
        val seed3 = Seed(bytes3)

        // Equals
        assertEquals(seed1, seed1)
        assertEquals(seed1, seed2)
        assertNotEquals(seed1, seed3)
        assertNotEquals(seed1, "not a seed")
        assertNotEquals(seed1, null)

        // HashCode
        assertEquals(seed1.hashCode(), seed2.hashCode())
        assertNotEquals(seed1.hashCode(), seed3.hashCode())

        // ToString
        assertNotNull(seed1.toString())
        assertTrue(seed1.toString().isNotEmpty())
    }

    @Test
    fun testStaticFactoryOf() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, zeroSeed)
        val key = AuthEncAES256ThenSHA256Key.generate(prng)

        val seed = Seed.of(key)
        assertEquals(32, seed.length)

        // Test empty key array throws
        try {
            Seed.of()
            fail("Expected Exception")
        } catch (_: Exception) {
            // Expected
        }
    }

    @Test
    fun testJvmStaticDelegatorViaReflection() {
        val seedClass = Seed::class.java
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, zeroSeed)
        val key = AuthEncAES256ThenSHA256Key.generate(prng)

        // We invoke Seed.of(AuthEncKey...)
        val ofMethod = seedClass.getMethod("of", Array<AuthEncKey>::class.java)
        val keysArray = java.lang.reflect.Array.newInstance(AuthEncKey::class.java, 1)
        java.lang.reflect.Array.set(keysArray, 0, key)

        val result = ofMethod.invoke(null, keysArray) as Seed
        assertEquals(32, result.length)
    }
}
