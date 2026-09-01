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

package io.olvid.engine.datatypes.key.symmetric

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.key.CryptographicKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.security.InvalidParameterException
import java.util.HashMap

abstract class MACKey
@Throws(InvalidParameterException::class)
constructor(
    algorithmImplementation: Byte,
    key: HashMap<DictionaryKey, Encoded>
) : SymmetricKey(CryptographicKey.ALGO_CLASS_MAC, algorithmImplementation, key) {

    val keyBytes: ByteArray = try {
        key[DictionaryKey(MACKEY_KEY_NAME)]!!.decodeBytes()
    } catch (_: DecodingException) {
        throw InvalidParameterException()
    }

    val keyLength: Int
        get() = keyBytes.size

    companion object {
        const val ALGO_IMPL_HMAC_SHA256: Byte = 0x00.toByte()
        const val MACKEY_KEY_NAME: String = "mackey"

        @JvmStatic
        fun of(algorithmImplementation: Byte, key: HashMap<DictionaryKey, Encoded>): MACKey? {
            return when (algorithmImplementation) {
                ALGO_IMPL_HMAC_SHA256 -> MACHmacSha256Key(key)
                else -> null
            }
        }
    }
}
