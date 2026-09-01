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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.UID
import java.nio.charset.StandardCharsets


class StringAndBoolean(@JvmField val string: String, @JvmField val bool: Boolean) {
    override fun equals(other: Any?): Boolean {
        if (other !is StringAndBoolean) {
            return false
        }
        return string == other.string && bool == other.bool
    }

    override fun hashCode(): Int {
        return string.hashCode() * 31 + bool.hashCode()
    }

    companion object {
        @JvmStatic
        fun computeUniqueUid(string: String, bool: Boolean): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            val input = ByteArray(string.toByteArray(StandardCharsets.UTF_8).size + 1)
            System.arraycopy(
                string.toByteArray(StandardCharsets.UTF_8),
                0,
                input,
                0,
                input.size - 1
            )
            input[input.size - 1] = if (bool) 0x01.toByte() else 0x00.toByte()
            return UID(sha256.digest(input))
        }
    }
    fun getString(): String = string
    fun getBool(): Boolean = bool
}
