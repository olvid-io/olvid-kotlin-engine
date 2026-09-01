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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.security.SecureRandom
import java.util.Base64

class ObvBase64Test {

    @Test
    fun testConstructor() {
        val obvBase64Instance = ObvBase64()
        org.junit.Assert.assertTrue(obvBase64Instance is ObvBase64)
    }

    @Test
    fun testJavaStaticDelegation() {
        val obvBase64Class = ObvBase64::class.java

        // 1. encode(ByteArray)
        val encoded = obvBase64Class.getMethod("encode", ByteArray::class.java).invoke(null, byteArrayOf(0x00)) as String
        // 2. decode(String)
        val decoded = obvBase64Class.getMethod("decode", String::class.java).invoke(null, encoded) as ByteArray
        assertArrayEquals(byteArrayOf(0x00), decoded)
    }

    @Test
    fun testRandom() {
        val random = SecureRandom()
        for (i in 0 until 100) {
            val len = random.nextInt(357) + 2
            val bytes = ByteArray(len)
            random.nextBytes(bytes)

            val base64 = ObvBase64.encode(bytes)
            val decoded = Base64.getDecoder().decode(base64.replace('_', '/').replace('-', '+'))
            val decoded2 = ObvBase64.decode(base64)

            assertArrayEquals(bytes, decoded)
            assertArrayEquals(bytes, decoded2)
        }
    }

    @Test
    fun testRandomAgain() {
        val random = SecureRandom()
        for (i in 0 until 100) {
            val len = random.nextInt(357) + 2
            val bytes = ByteArray(len)
            random.nextBytes(bytes)

            val base64 = Base64.getEncoder().withoutPadding().encodeToString(bytes).replace('/', '_').replace('+', '-')
            val base642 = ObvBase64.encode(bytes)
            val decoded = ObvBase64.decode(base64)

            assertEquals(base64, base642)
            assertArrayEquals(bytes, decoded)
        }
    }

    @Test
    fun testEdgeCases() {
        // Test 0: Empty array (existing engine behavior yields a single null character)
        assertEquals("\u0000", ObvBase64.encode(byteArrayOf()))
        assertArrayEquals(byteArrayOf(), ObvBase64.decode(""))

        // Test 1: Explicit lengths to trigger different modulo 3 leftovers
        // Length 1 (modulo 3 leftover 1)
        val bytes1 = byteArrayOf(0x41) // 'A'
        val encoded1 = ObvBase64.encode(bytes1)
        assertArrayEquals(bytes1, ObvBase64.decode(encoded1))

        // Length 2 (modulo 3 leftover 2)
        val bytes2 = byteArrayOf(0x41, 0x42) // 'A', 'B'
        val encoded2 = ObvBase64.encode(bytes2)
        assertArrayEquals(bytes2, ObvBase64.decode(encoded2))

        // Length 3 (modulo 3 leftover 0)
        val bytes3 = byteArrayOf(0x41, 0x42, 0x43) // 'A', 'B', 'C'
        val encoded3 = ObvBase64.encode(bytes3)
        assertArrayEquals(bytes3, ObvBase64.decode(encoded3))

        // Test decoding with padding equals character '='
        assertArrayEquals(bytes1, ObvBase64.decode("$encoded1=="))
        assertArrayEquals(bytes2, ObvBase64.decode("$encoded2="))
    }

    @Test
    fun testDecodingFailures() {
        // Test invalid modulo 4 lengths (length mod 4 == 1)
        try {
            ObvBase64.decode("A")
            fail("Expected exception for invalid modulo 4 length")
        } catch (_: Exception) {
        }

        // Test invalid character sets (contains non-Base64 characters like whitespace, +, /, *, etc.)
        try {
            ObvBase64.decode("A+BC")
            fail("Expected exception for character outside custom alphabet")
        } catch (_: Exception) {
        }

        try {
            ObvBase64.decode("A/BC")
            fail("Expected exception for character outside custom alphabet")
        } catch (_: Exception) {
        }

        try {
            ObvBase64.decode("A*BC")
            fail("Expected exception for character outside custom alphabet")
        } catch (_: Exception) {
        }
    }
}
