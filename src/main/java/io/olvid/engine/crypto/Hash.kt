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

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

interface Hash {
    fun outputLength(): Int
    fun digest(data: ByteArray?): ByteArray

    companion object {
        const val SHA256: String = "sha-256"
        const val SHA512: String = "sha-512"
    }
}


internal class HashSHA256 : Hash {
    private var h: MessageDigest? = null

    init {
        try {
            h = MessageDigest.getInstance("SHA-256")
        } catch (_: NoSuchAlgorithmException) { }
    }

    override fun outputLength(): Int {
        return OUTPUT_LENGTH
    }

    override fun digest(data: ByteArray?): ByteArray {
        return h!!.digest(data)
    }

    companion object {
        const val OUTPUT_LENGTH: Int = 32
    }
}

internal class HashSHA512 : Hash {
    private var h: MessageDigest? = null

    init {
        try {
            h = MessageDigest.getInstance("SHA-512")
        } catch (_: NoSuchAlgorithmException) {
        }
    }

    override fun outputLength(): Int {
        return OUTPUT_LENGTH
    }

    override fun digest(data: ByteArray?): ByteArray {
        return h!!.digest(data)
    }

    companion object {
        const val OUTPUT_LENGTH: Int = 64
    }
}