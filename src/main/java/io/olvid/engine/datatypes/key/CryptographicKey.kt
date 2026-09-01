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
package io.olvid.engine.datatypes.key

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.encoder.Encoded


abstract class CryptographicKey protected constructor(
    @JvmField val algorithmClass: Byte,
    @JvmField val algorithmImplementation: Byte,
    val key: HashMap<DictionaryKey, Encoded>
) {
    override fun equals(other: Any?): Boolean {
        if (other !is CryptographicKey) {
            return false
        }
        if ((other.algorithmClass != algorithmClass) || (other.algorithmImplementation != algorithmImplementation)) {
            return false
        }
        return key == other.key
    }

    override fun hashCode(): Int {
        return key.hashCode() + 31 * algorithmClass + 631 * algorithmImplementation
    }

    companion object {
        val ALGO_CLASS_SYMMETRIC_ENCRYPTION: Byte = 0x00.toByte()
        val ALGO_CLASS_MAC: Byte = 0x01.toByte()
        val ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION: Byte = 0x02.toByte()

        val ALGO_CLASS_SIGNATURE: Byte = 0x11.toByte()
        val ALGO_CLASS_PUBLIC_KEY_ENCRYPTION: Byte = 0x12.toByte()
        val ALGO_CLASS_SERVER_AUTHENTICATION: Byte = 0x14.toByte()
    }
}