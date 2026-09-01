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

package io.olvid.engine.datatypes.key.asymmetric

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.key.CryptographicKey
import io.olvid.engine.encoder.Encoded
import java.util.HashMap

abstract class PublicKey(
    algorithmClass: Byte,
    algorithmImplementation: Byte,
    key: HashMap<DictionaryKey, Encoded>
) : CryptographicKey(algorithmClass, algorithmImplementation, key) {

    companion object {
        @JvmStatic
        fun of(algorithmClass: Byte, algorithmImplementation: Byte, key: HashMap<DictionaryKey, Encoded>): PublicKey? {
            return when (algorithmClass) {
                CryptographicKey.ALGO_CLASS_PUBLIC_KEY_ENCRYPTION -> EncryptionPublicKey.of(algorithmImplementation, key)
                CryptographicKey.ALGO_CLASS_SIGNATURE -> SignaturePublicKey.of(algorithmImplementation, key)
                CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION -> ServerAuthenticationPublicKey.of(algorithmImplementation, key)
                else -> null
            }
        }
    }
}
