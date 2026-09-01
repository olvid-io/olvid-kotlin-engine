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

import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded

class Chunk(
    @JvmField val chunkNumber: Int,
    @JvmField val data: ByteArray
) {

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encodedChunk: Encoded): Chunk {
            val list = encodedChunk.decodeList()
            return Chunk(list[0].decodeLong().toInt(), list[1].decodeBytes())
        }

        @JvmStatic
        fun lengthOfEncodedChunkFromLengthOfInnerData(length: Int): Int {
            return length + 3 * Encoded.ENCODED_HEADER_LENGTH + Encoded.INT_ENCODING_LENGTH
        }

        @JvmStatic
        fun lengthOfInnerDataFromLengthOfEncodedChunk(length: Int): Int {
            return length - 3 * Encoded.ENCODED_HEADER_LENGTH - Encoded.INT_ENCODING_LENGTH
        }
    }

    fun encode(): Encoded {
        return Encoded.of(arrayOf<Encoded>(Encoded.of(chunkNumber.toLong()), Encoded.of(data)))
    }
}
