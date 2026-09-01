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
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger

class UIDTest {

    @Test
    fun testConstructorWithByteArray() {
        val validBytes = ByteArray(UID.UID_LENGTH) { it.toByte() }
        val uid = UID(validBytes)
        assertArrayEquals(validBytes, uid.bytes)

        // Invalid lengths should throw IllegalArgumentException
        try {
            UID(ByteArray(UID.UID_LENGTH - 1))
            fail("Expected IllegalArgumentException for too short array")
        } catch (_: IllegalArgumentException) {
        }

        try {
            UID(ByteArray(UID.UID_LENGTH + 1))
            fail("Expected IllegalArgumentException for too long array")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun testConstructorWithHexString() {
        val hexString = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val uid = UID(hexString)
        assertEquals(hexString.uppercase(), uid.toString())

        // Too short or invalid hex string length
        try {
            UID("000102")
            fail("Expected exception for invalid hex string length")
        } catch (_: Exception) {
        }
    }

    @Test
    fun testConstructorWithPRNG() {
        val mockPrng = object : PRNG {
            override fun bytes(l: Int): ByteArray {
                return ByteArray(l) { i -> i.toByte() }
            }
            override fun bigInt(n: BigInteger): BigInteger {
                return BigInteger.ZERO
            }
        }
        val uid = UID(mockPrng)
        val expectedBytes = ByteArray(UID.UID_LENGTH) { it.toByte() }
        assertArrayEquals(expectedBytes, uid.bytes)
    }

    @Test
    fun testFromLong() {
        val l = 0x1122334455667788L
        val uid = UID.fromLong(l)
        val bytes = uid.bytes
        
        assertEquals(0x88.toByte(), bytes[0])
        assertEquals(0x77.toByte(), bytes[1])
        assertEquals(0x66.toByte(), bytes[2])
        assertEquals(0x55.toByte(), bytes[3])
        assertEquals(0x44.toByte(), bytes[4])
        assertEquals(0x33.toByte(), bytes[5])
        assertEquals(0x22.toByte(), bytes[6])
        assertEquals(0x11.toByte(), bytes[7])
        
        // Remaining bytes should be 0
        for (i in 8 until UID.UID_LENGTH) {
            assertEquals(0.toByte(), bytes[i])
        }
    }

    @Test
    fun testEqualsAndHashCode() {
        val bytes1 = ByteArray(UID.UID_LENGTH) { 1 }
        val bytes2 = ByteArray(UID.UID_LENGTH) { 1 }
        val bytes3 = ByteArray(UID.UID_LENGTH) { 2 }

        val uid1 = UID(bytes1)
        val uid2 = UID(bytes2)
        val uid3 = UID(bytes3)

        // Reflexive
        assertEquals(uid1, uid1)
        
        // Symmetric
        assertEquals(uid1, uid2)
        assertEquals(uid2, uid1)
        assertEquals(uid1.hashCode(), uid2.hashCode())

        // Unequal
        assertNotEquals(uid1, uid3)
        assertNotEquals(uid1, null)
        assertNotEquals(uid1, "some string")

        // Hash code should be unequal for different values
        assertNotEquals(uid1.hashCode(), uid3.hashCode())
    }

    @Test
    fun testCompareTo() {
        val bytes1 = ByteArray(UID.UID_LENGTH) { 1 }
        val bytes2 = ByteArray(UID.UID_LENGTH) { 1 }
        val bytes3 = ByteArray(UID.UID_LENGTH) { 1 }
        bytes3[10] = 2 // Greater

        val bytes4 = ByteArray(UID.UID_LENGTH) { 1 }
        bytes4[10] = 0 // Less

        val uid1 = UID(bytes1)
        val uid2 = UID(bytes2)
        val uid3 = UID(bytes3)
        val uid4 = UID(bytes4)

        assertEquals(0, uid1.compareTo(uid2))
        assertTrue(uid1.compareTo(uid3) < 0)
        assertTrue(uid1.compareTo(uid4) > 0)
    }

    @Test
    fun testJavaStaticDelegation() {
        val uidClass = UID::class.java
        val fromLongMethod = uidClass.getMethod("fromLong", Long::class.javaPrimitiveType)
        val uid = fromLongMethod.invoke(null, 12L) as UID
        assertEquals(12.toByte(), uid.bytes[0])
    }
}
