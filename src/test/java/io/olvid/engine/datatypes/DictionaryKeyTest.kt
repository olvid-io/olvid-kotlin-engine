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
import java.nio.charset.StandardCharsets

class DictionaryKeyTest {

    @Test
    fun testConstructors() {
        val rawBytes = "hello".toByteArray(StandardCharsets.UTF_8)
        val keyFromBytes = DictionaryKey(rawBytes)
        assertArrayEquals(rawBytes, keyFromBytes.data)

        val keyFromString = DictionaryKey("hello")
        assertArrayEquals(rawBytes, keyFromString.data)
    }

    @Test
    fun testGetString() {
        val key = DictionaryKey("test_string")
        assertEquals("test_string", key.getString())
    }

    @Test
    fun testEqualsAndHashCode() {
        val key1 = DictionaryKey("test")
        val key2 = DictionaryKey("test")
        val key3 = DictionaryKey("different")

        // Reflexive & Symmetric
        assertEquals(key1, key1)
        assertEquals(key1, key2)
        assertEquals(key2, key1)
        assertNotEquals(key1, key3)
        assertNotEquals(key1, "not a dictionary key")
        assertNotEquals(key1, null)

        // HashCode consistency
        assertEquals(key1.hashCode(), key2.hashCode())
        assertNotEquals(key1.hashCode(), key3.hashCode())
    }

    @Test
    fun testNullChecks() {
        // Test byte array constructor with null
        try {
            val nullBytes: ByteArray? = null
            DictionaryKey(nullBytes!!)
            fail("Expected NullPointerException")
        } catch (_: NullPointerException) {
            // Expected
        }

        // Test string constructor with null
        try {
            val nullString: String? = null
            DictionaryKey(nullString!!)
            fail("Expected NullPointerException")
        } catch (_: NullPointerException) {
            // Expected
        }
    }
}
