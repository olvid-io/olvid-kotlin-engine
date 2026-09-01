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

class EncryptedBytesTest {

    @Test
    fun testConstructorAndGetters() {
        val testBytes = byteArrayOf(1, 2, 3, 4, 5)
        val encrypted = EncryptedBytes(testBytes)
        
        assertEquals(5, encrypted.length)
        assertArrayEquals(testBytes, encrypted.bytes)
    }

    @Test
    fun testEquals() {
        val bytes1 = byteArrayOf(1, 2, 3)
        val bytes2 = byteArrayOf(1, 2, 3)
        val bytes3 = byteArrayOf(1, 2, 4)

        val enc1 = EncryptedBytes(bytes1)
        val enc2 = EncryptedBytes(bytes2)
        val enc3 = EncryptedBytes(bytes3)

        // Reflexive
        assertEquals(enc1, enc1)

        // Symmetric and equal
        assertEquals(enc1, enc2)
        assertEquals(enc2, enc1)

        // Not equal values
        assertNotEquals(enc1, enc3)

        // Null and different types
        assertNotEquals(enc1, null)
        assertNotEquals(enc1, "not an EncryptedBytes")
    }
}
