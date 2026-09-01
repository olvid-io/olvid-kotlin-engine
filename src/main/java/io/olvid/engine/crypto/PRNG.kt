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

import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.symmetric.MACHmacSha256Key
import java.math.BigInteger
import java.util.Arrays
import kotlin.math.min

interface PRNG {
    fun bytes(l: Int): ByteArray
    fun bigInt(n: BigInteger): BigInteger

    companion object {
        const val PRNG_HMAC_SHA256: String = "prng_hmac_sha-256"
    }
}

internal class PRNGHmacSHA256(seed: Seed) : PRNG {
    @JvmField var state_k: ByteArray = ByteArray(MACHmacSha256Key.KEY_BYTE_LENGTH)
    @JvmField var state_v: ByteArray = ByteArray(MACHmacSha256.OUTPUT_LENGTH)

    init {
        Arrays.fill(state_k, 0.toByte())
        Arrays.fill(state_v, 1.toByte())
        update(seed.getBytes())
    }

    private fun update(data: ByteArray) {
        try {
            val `in` = ByteArray(state_v.size + 1 + data.size)
            System.arraycopy(state_v, 0, `in`, 0, state_v.size)
            `in`[state_v.size] = 0
            System.arraycopy(data, 0, `in`, state_v.size + 1, data.size)
            state_k = MACHmacSha256().digest(MACHmacSha256Key.of(state_k), `in`)!!
            state_v = MACHmacSha256().digest(MACHmacSha256Key.of(state_k), state_v)!!
            if (data.isNotEmpty()) {
                System.arraycopy(state_v, 0, `in`, 0, state_v.size)
                `in`[state_v.size] = 1
                System.arraycopy(data, 0, `in`, state_v.size + 1, data.size)
                state_k = MACHmacSha256().digest(MACHmacSha256Key.of(state_k), `in`)!!
                state_v = MACHmacSha256().digest(MACHmacSha256Key.of(state_k), state_v)!!
            }
        } catch (_: Exception) { }
    }

    fun reseed(seed: Seed) {
        update(seed.getBytes())
    }

    override fun bytes(l: Int): ByteArray {
        val output = ByteArray(l)
        for (i in 0..<1 + (l - 1) / MACHmacSha256.OUTPUT_LENGTH) {
            try {
                state_v = MACHmacSha256().digest(MACHmacSha256Key.of(state_k), state_v)!!
                System.arraycopy(
                    state_v,
                    0,
                    output,
                    i * MACHmacSha256.OUTPUT_LENGTH,
                    min(
                        MACHmacSha256.OUTPUT_LENGTH,
                        l - i * MACHmacSha256.OUTPUT_LENGTH
                    )
                )
            } catch (_: Exception) { }
        }
        update(ByteArray(0))
        return output
    }

    override fun bigInt(n: BigInteger): BigInteger {
        val n_minus_one = n.subtract(BigInteger.ONE)
        val l = n_minus_one.bitLength()
        val ell = 1 + (l - 1) / 8
        val mask = (1 shl (l - 8 * (ell - 1))) - 1
        while (true) {
            val rand = bytes(ell)
            rand[0] = (rand[0].toInt() and mask).toByte()
            val r = BigInteger(1, rand)
            if (r < n) {
                return r
            }
        }
    }
}