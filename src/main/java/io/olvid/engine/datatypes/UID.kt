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
import io.olvid.engine.crypto.PRNG

class UID : Comparable<UID> {
    companion object {
        const val UID_LENGTH = 32

        @JvmStatic
        fun fromLong(l: Long): UID {
            val bytes = ByteArray(UID_LENGTH)
            bytes[0] = (l and 0xff).toByte()
            bytes[1] = ((l shr 8) and 0xff).toByte()
            bytes[2] = ((l shr 16) and 0xff).toByte()
            bytes[3] = ((l shr 24) and 0xff).toByte()
            bytes[4] = ((l shr 32) and 0xff).toByte()
            bytes[5] = ((l shr 40) and 0xff).toByte()
            bytes[6] = ((l shr 48) and 0xff).toByte()
            bytes[7] = ((l shr 56) and 0xff).toByte()
            return UID(bytes)
        }
    }

    @JvmField var bytes: ByteArray = ByteArray(0)

    constructor(uid: ByteArray) {
        if (uid.size != UID_LENGTH) {
            throw IllegalArgumentException()
        }
        this.bytes = uid
    }

    constructor(uidHexString: String) : this(Logger.fromHexString(uidHexString))

    constructor(prng: PRNG) : this(prng.bytes(UID_LENGTH))

    override fun toString(): String {
        return Logger.toHexString(bytes)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UID) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    override fun compareTo(other: UID): Int {
        for (i in 0 until UID_LENGTH) {
            if (this.bytes[i] != other.bytes[i]) {
                return (this.bytes[i].toInt() and 0xff) - (other.bytes[i].toInt() and 0xff)
            }
        }
        return 0
    }
}
