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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.encoder.Encoded
import java.util.Arrays
import java.util.HashMap

class AuthEncAES256ThenSHA256Key(key: HashMap<DictionaryKey, Encoded>) : AuthEncKey(ALGO_IMPL_AES256_THEN_SHA256, key) {

    @JvmField val macKey: MACHmacSha256Key = MACHmacSha256Key(key)
    @JvmField val encKey: SymEncCTRAES256Key = SymEncCTRAES256Key(key)

    override fun toString(): String {
        return Logger.toHexString(macKey.keyBytes) + " - " + Logger.toHexString(encKey.keyBytes)
    }

    companion object {
        @JvmStatic
        fun of(macKey: ByteArray, encKey: ByteArray): AuthEncAES256ThenSHA256Key {
            val key = HashMap<DictionaryKey, Encoded>()
            key[DictionaryKey(MACKey.MACKEY_KEY_NAME)] = Encoded.of(macKey)
            key[DictionaryKey(SymEncKey.SYMENC_KEY_NAME)] = Encoded.of(encKey)
            return AuthEncAES256ThenSHA256Key(key)
        }

        @JvmStatic
        fun generate(prng: PRNG): AuthEncAES256ThenSHA256Key {
            val bytes = prng.bytes(MACHmacSha256Key.KEY_BYTE_LENGTH + SymEncCTRAES256Key.KEY_BYTE_LENGTH)
            return of(
                Arrays.copyOfRange(bytes, 0, MACHmacSha256Key.KEY_BYTE_LENGTH),
                Arrays.copyOfRange(bytes, MACHmacSha256Key.KEY_BYTE_LENGTH, MACHmacSha256Key.KEY_BYTE_LENGTH + SymEncCTRAES256Key.KEY_BYTE_LENGTH)
            )
        }
    }
}
