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
package io.olvid.engine.crypto

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.util.Arrays


object ProofOfWorkEngine {
    private const val N = 256 // the number of columns of the matrix
    private const val R = 128 // the number of lines of the matrix, must be a multiple of 64
    private const val W = 4 // the weight of the target syndrome - to be on GV, binom(N,W) = 2**R. Must be 4.

    private fun generateMatrix(seed: Seed?): Array<Column?> {
        val H = arrayOfNulls<Column>(N)
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed!!)
        val bytes = prng.bytes(N * R / 8)
        for (i in 0..<N) {
            H[i] = Column(intArrayOf(i), bytes, i * R / 8)
        }
        return H
    }

    @Throws(DecodingException::class)
    @JvmStatic
    fun solveChallenge(challenge: Encoded): Encoded? {
        val list: Array<Encoded> = challenge.decodeList()
        if (list.size != 2) {
            throw DecodingException()
        }
        val seed = list[0].decodeSeed()
        val Sbytes = list[1].decodeBytes()
        if (Sbytes.size != R / 8) {
            throw DecodingException()
        }
        val S = Column(intArrayOf(), Sbytes)
        val H = generateMatrix(seed)

        val setHalf = HashSet<Column>()
        val setHalfS = HashSet<Column>()

        for (i in 1..<N) {
            for (j in 0..<i) {
                val xor = H[i]!!.xor(H[j]!!)
                setHalf.add(xor)
                setHalfS.add(xor.xor(S))
            }
        }

        setHalf.retainAll(setHalfS)

        for (col in setHalf) {
            val single = HashSet<Column>()
            single.add(col)
            setHalfS.retainAll(single)
            for (col2 in setHalfS) {
                val indexes = col.xor(col2).indexes
                Arrays.sort(indexes)
                val encodedIndexes = arrayOfNulls<Encoded>(indexes.size)
                for (i in indexes.indices) {
                    encodedIndexes[i] = Encoded.of(indexes[i].toLong())
                }
                @Suppress("UNCHECKED_CAST")
                return Encoded.of(encodedIndexes as Array<Encoded>)
            }
            break
        }
        Logger.w("No solution was found for this challenge...")
        return null
    }

    private class Column {
        val `val`: LongArray = LongArray(R / 64)
        val indexes: IntArray

        internal constructor(indexes: IntArray, bytes: ByteArray) {
            this.indexes = indexes
            for (i in bytes.indices) {
                `val`[i / 8] =
                    `val`[i / 8] xor (((bytes[i].toInt() and 0xff).toLong()) shl ((i and 7) * 8))
            }
        }

        internal constructor(indexes: IntArray, bytes: ByteArray, offset: Int) {
            this.indexes = indexes
            for (i in 0..<R / 8) {
                `val`[i / 8] =
                    `val`[i / 8] xor (((bytes[offset + i].toInt() and 0xff).toLong()) shl ((i and 7) * 8))
            }
        }

        internal constructor(indexes: IntArray, `val`: LongArray) {
            this.indexes = indexes
            System.arraycopy(`val`, 0, this.`val`, 0, R / 64)
        }

        fun xor(other: Column): Column {
            val xorVal = LongArray(`val`.size)
            for (i in `val`.indices) {
                xorVal[i] = `val`[i] xor other.`val`[i]
            }
            val xoredIndexes = IntArray(indexes.size + other.indexes.size)
            System.arraycopy(indexes, 0, xoredIndexes, 0, indexes.size)
            System.arraycopy(other.indexes, 0, xoredIndexes, indexes.size, other.indexes.size)
            return Column(xoredIndexes, xorVal)
        }

        override fun equals(other: Any?): Boolean {
            return (other is Column) && `val`.contentEquals(other.`val`)
        }

        override fun hashCode(): Int {
            return `val`.contentHashCode()
        }
    }
}
