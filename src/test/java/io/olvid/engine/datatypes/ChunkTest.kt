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

import io.olvid.engine.encoder.Encoded
import org.junit.Assert.*
import org.junit.Test

class ChunkTest {

    @Test
    fun testConstructorAndGetters() {
        val testData = byteArrayOf(10, 20, 30)
        val chunk = Chunk(42, testData)

        assertEquals(42, chunk.chunkNumber)
        assertArrayEquals(testData, chunk.data)
    }

    @Test
    fun testEncodeAndDecode() {
        val testData = byteArrayOf(5, 6, 7, 8)
        val chunk = Chunk(123, testData)

        val encoded = chunk.encode()
        assertNotNull(encoded)

        val decoded = Chunk.of(encoded)
        assertEquals(chunk.chunkNumber, decoded.chunkNumber)
        assertArrayEquals(chunk.data, decoded.data)
    }

    @Test
    fun testLengthCalculations() {
        val innerLength = 100
        val encodedLength = Chunk.lengthOfEncodedChunkFromLengthOfInnerData(innerLength)
        val calculatedInnerLength = Chunk.lengthOfInnerDataFromLengthOfEncodedChunk(encodedLength)
        
        assertEquals(innerLength, calculatedInnerLength)
    }

    @Test
    fun testJvmStaticDelegation() {
        // Test 'of' static delegation method via reflection
        val testData = byteArrayOf(9, 8, 7)
        val chunk = Chunk(999, testData)
        val encoded = chunk.encode()

        val ofMethod = Chunk::class.java.getMethod("of", Encoded::class.java)
        val decoded = ofMethod.invoke(null, encoded) as Chunk
        assertEquals(999, decoded.chunkNumber)
        assertArrayEquals(testData, decoded.data)

        // Test 'lengthOfEncodedChunkFromLengthOfInnerData' static delegation method via reflection
        val lenMethod = Chunk::class.java.getMethod("lengthOfEncodedChunkFromLengthOfInnerData", Int::class.javaPrimitiveType)
        val encodedLen = lenMethod.invoke(null, 50) as Int
        assertEquals(Chunk.lengthOfEncodedChunkFromLengthOfInnerData(50), encodedLen)

        // Test 'lengthOfInnerDataFromLengthOfEncodedChunk' static delegation method via reflection
        val innerMethod = Chunk::class.java.getMethod("lengthOfInnerDataFromLengthOfEncodedChunk", Int::class.javaPrimitiveType)
        val innerLen = innerMethod.invoke(null, encodedLen) as Int
        assertEquals(50, innerLen)
    }
}
