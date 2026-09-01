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
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import java.security.InvalidParameterException


interface KDF {
    @Throws(InvalidParameterException::class)
    fun gen(seed: Seed?, delegate: Delegate): Array<SymmetricKey>

    interface Delegate {
        fun getKeyLength(): Int
        fun processBytes(bytes: ByteArray): Array<SymmetricKey>
    }

    companion object {
        // WARNING: all KDF implementations must rely on a PRNG behaving as a random oracle. This is required for the security proof of ECIES.
        const val KDF_SHA256: String = "kdf_sha-256"
    }
}

internal class KDFSha256 : KDF {
    @Throws(InvalidParameterException::class)
    override fun gen(seed: Seed?, delegate: KDF.Delegate): Array<SymmetricKey> {
        val prng = PRNGHmacSHA256(seed!!)
        val bytes = prng.bytes(delegate.getKeyLength())
        return delegate.processBytes(bytes)
    }
}
