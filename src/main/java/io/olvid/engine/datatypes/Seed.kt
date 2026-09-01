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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Hash
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import java.util.Arrays

class Seed {

    @JvmField
    var bytes: ByteArray = ByteArray(0)

    @JvmField
    var length: Int = 0

    companion object {
        const val MIN_SEED_LENGTH = 32

        @JvmStatic
        @Throws(Exception::class)
        fun of(vararg authEncKeys: AuthEncKey): Seed {
            if (authEncKeys.isEmpty()) {
                throw Exception()
            }
            val zeroSeed = Seed(ByteArray(MIN_SEED_LENGTH))
            val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, zeroSeed)

            val ciphertexts = arrayOfNulls<EncryptedBytes>(authEncKeys.size)
            var ciphertextsLength = 0
            for (i in authEncKeys.indices) {
                val authEnc = Suite.getAuthEnc(authEncKeys[i])!!
                val ct = authEnc.encrypt(authEncKeys[i], ByteArray(MIN_SEED_LENGTH), prng)
                ciphertexts[i] = ct
                ciphertextsLength += ct.length
            }

            val hashInput = ByteArray(ciphertextsLength)
            ciphertextsLength = 0
            for (i in authEncKeys.indices) {
                val ct = ciphertexts[i]!!
                System.arraycopy(ct.bytes, 0, hashInput, ciphertextsLength, ct.length)
                ciphertextsLength += ct.length
            }

            val hash = Suite.getHash(Hash.SHA256)
            return Seed(hash.digest(hashInput))
        }
    }

    constructor(bytes: ByteArray) {
        if (bytes.size < MIN_SEED_LENGTH) {
            throw IllegalArgumentException()
        }
        this.bytes = bytes
        this.length = bytes.size
    }

    constructor(vararg seedsToConcatenate: Seed) {
        var totalLen = 0
        for (seed in seedsToConcatenate) {
            totalLen += seed.length
        }
        this.bytes = ByteArray(totalLen)
        this.length = totalLen
        var offset = 0
        for (seed in seedsToConcatenate) {
            System.arraycopy(seed.bytes, 0, this.bytes, offset, seed.length)
            offset += seed.length
        }
    }

    constructor(prng: PRNG) : this(prng.bytes(MIN_SEED_LENGTH))

    fun getBytes(): ByteArray {
        return bytes
    }

    override fun toString(): String {
        return Logger.toHexString(bytes)
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(bytes)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Seed) return false
        return bytes.contentEquals(other.bytes)
    }
}
