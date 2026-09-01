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
import io.olvid.engine.encoder.Encoded
import java.security.InvalidParameterException
import java.util.HashMap

class MACHmacSha256Key
@Throws(InvalidParameterException::class)
constructor(key: HashMap<DictionaryKey, Encoded>) : MACKey(ALGO_IMPL_HMAC_SHA256, key) {

    init {
        if (keyLength < KEY_BYTE_LENGTH) {
            throw InvalidParameterException()
        }
    }

    companion object {
        const val KEY_BYTE_LENGTH: Int = 32

        @JvmStatic
        fun of(macKey: ByteArray): MACHmacSha256Key {
            val key = HashMap<DictionaryKey, Encoded>()
            key[DictionaryKey(MACKEY_KEY_NAME)] = Encoded.of(macKey)
            return MACHmacSha256Key(key)
        }
    }
}
