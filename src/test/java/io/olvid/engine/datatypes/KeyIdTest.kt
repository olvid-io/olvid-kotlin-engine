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

import org.junit.Assert.*
import org.junit.Test

class KeyIdTest {

    @Test
    fun testConstructorAndGetters() {
        val validBytes = ByteArray(KeyId.KEYID_LENGTH) { it.toByte() }
        val keyId = KeyId(validBytes)
        assertArrayEquals(validBytes, keyId.bytes)
    }

    @Test
    fun testConstructorWithInvalidLengths() {
        try {
            KeyId(ByteArray(KeyId.KEYID_LENGTH - 1))
            fail("Expected IllegalArgumentException for too short array")
        } catch (_: IllegalArgumentException) {
        }

        try {
            KeyId(ByteArray(KeyId.KEYID_LENGTH + 1))
            fail("Expected IllegalArgumentException for too long array")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun testToString() {
        val validBytes = ByteArray(KeyId.KEYID_LENGTH) { 0x0F.toByte() }
        val keyId = KeyId(validBytes)
        val expectedHex = "0f".repeat(32)
        assertEquals(expectedHex.uppercase(), keyId.toString().uppercase())
    }

    @Test
    fun testEquals() {
        val bytes1 = ByteArray(KeyId.KEYID_LENGTH) { 1 }
        val bytes2 = ByteArray(KeyId.KEYID_LENGTH) { 1 }
        val bytes3 = ByteArray(KeyId.KEYID_LENGTH) { 2 }

        val keyId1 = KeyId(bytes1)
        val keyId2 = KeyId(bytes2)
        val keyId3 = KeyId(bytes3)

        // Reflexive
        assertEquals(keyId1, keyId1)

        // Symmetric and equal
        assertEquals(keyId1, keyId2)
        assertEquals(keyId2, keyId1)

        // Not equal values
        assertNotEquals(keyId1, keyId3)

        // Null and different types
        assertNotEquals(keyId1, null)
        assertNotEquals(keyId1, "not a KeyId")
    }
}
