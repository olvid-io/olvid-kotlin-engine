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

abstract class ServerAuthenticationPrivateKey(
    algorithmImplementation: Byte,
    key: HashMap<DictionaryKey, Encoded>
) : PrivateKey(
    CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION, algorithmImplementation, key
) {
    @get:Throws(Exception::class)
    open val signaturePrivateKey: SignaturePrivateKey
        get() {
            return when (algorithmImplementation) {
                ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC,
                ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 ->
                    (this as ServerAuthenticationECSdsaPrivateKey).signaturePrivateKey
                else -> throw Exception("This server authentication private key does not implement signature")
            }
        }

    companion object {
        @JvmStatic
        fun of(
            algorithmImplementation: Byte,
            key: HashMap<DictionaryKey, Encoded>
        ): ServerAuthenticationPrivateKey? {
            return when (algorithmImplementation) {
                ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC ->
                    ServerAuthenticationECSdsaMDCPrivateKey(key)
                ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 ->
                    ServerAuthenticationECSdsaCurve25519PrivateKey(key)
                else -> null
            }
        }
    }
}
