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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import kotlin.math.min

object SAS {
    @JvmStatic
    fun compute(seedAlice: Seed, seedBob: Seed?, numberOfDigits: Int): ByteArray? {
        val seed = Seed(seedAlice, seedBob!!)
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
        val max = BigInteger.valueOf(10).pow(numberOfDigits)
        val sas = prng.bigInt(max)
            .add(max) // We add max to the sas to be able to get the 0 padding by simply removing the first character of the String
        return sas.toString(10).substring(1).toByteArray(StandardCharsets.UTF_8)
    }

    @JvmStatic
    fun computeDouble(
        seedAlice: Seed,
        seedBob: Seed,
        identityBob: Identity,
        numberOfDigits: Int
    ): ByteArray? {
        val sha256 = Suite.getHash(Hash.SHA256)
        val bytesIdentity = identityBob.getBytes()
        val toHash = ByteArray(bytesIdentity.size + seedAlice.length)
        System.arraycopy(bytesIdentity, 0, toHash, 0, bytesIdentity.size)
        System.arraycopy(seedAlice.getBytes(), 0, toHash, bytesIdentity.size, seedAlice.length)
        val hash = sha256.digest(toHash)

        val xor = ByteArray(min(hash.size, seedBob.length))
        for (i in xor.indices) {
            xor[i] = (seedBob.getBytes()[i].toInt() xor hash[i].toInt()).toByte()
        }

        val seed = Seed(xor)
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
        val max = BigInteger.valueOf(10).pow(2 * numberOfDigits)
        val sas = prng.bigInt(max)
            .add(max) // We add max to the sas to be able to get the 0 padding by simply removing the first character of the String
        return sas.toString(10).substring(1).toByteArray(StandardCharsets.UTF_8)
    }

    @JvmStatic
    fun computeSimple(
        seedAlice: Seed,
        seedBob: Seed,
        rawPublicKeyBob: ByteArray,
        numberOfDigits: Int
    ): String {
        val sha256 = Suite.getHash(Hash.SHA256)
        val toHash = ByteArray(rawPublicKeyBob.size + seedAlice.length)
        System.arraycopy(rawPublicKeyBob, 0, toHash, 0, rawPublicKeyBob.size)
        System.arraycopy(seedAlice.getBytes(), 0, toHash, rawPublicKeyBob.size, seedAlice.length)
        val hash = sha256.digest(toHash)

        val xor = ByteArray(min(hash.size, seedBob.length))
        for (i in xor.indices) {
            xor[i] = (seedBob.getBytes()[i].toInt() xor hash[i].toInt()).toByte()
        }

        val seed = Seed(xor)
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
        val max = BigInteger.valueOf(10).pow(numberOfDigits)
        val sas = prng.bigInt(max)
            .add(max) // We add max to the sas to be able to get the 0 padding by simply removing the first character of the String
        return sas.toString(10).substring(1)
    }
}
