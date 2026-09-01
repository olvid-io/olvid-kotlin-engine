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
import java.math.BigInteger
import java.security.SecureRandom

interface PRNGService : PRNG {
    fun reseed(seed: Seed?)
}

internal class PRNGServiceHmacSHA256 private constructor() : PRNGService {
    private val rand: SecureRandom = SecureRandom()
    var prng: PRNGHmacSHA256
    var reseedCounter: Int

    init {
        val seedBytes = ByteArray(Seed.MIN_SEED_LENGTH)
        rand.nextBytes(seedBytes)
        prng = PRNGHmacSHA256(Seed(seedBytes))
        reseedCounter = 1
    }

    @Synchronized
    override fun reseed(seed: Seed?) {
        prng = PRNGHmacSHA256(seed!!)
        reseedCounter = 0
    }

    @Synchronized
    override fun bytes(l: Int): ByteArray {
        val output = prng.bytes(l)
        if (reseedCounter == RESEED_FREQUENCY) {
            val seedBytes = ByteArray(Seed.MIN_SEED_LENGTH)
            rand.nextBytes(seedBytes)
            prng.reseed(Seed(seedBytes))
            reseedCounter = 1
        } else {
            reseedCounter++
        }
        return output
    }

    @Synchronized
    override fun bigInt(n: BigInteger): BigInteger {
        return prng.bigInt(n)
    }

    companion object {
        const val RESEED_FREQUENCY: Int = 100
        val instance: PRNGServiceHmacSHA256 = PRNGServiceHmacSHA256()
    }
}
