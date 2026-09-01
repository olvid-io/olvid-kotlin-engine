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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.util.HashMap

abstract class ServerAuthenticationPublicKey(
    algorithmImplementation: Byte,
    key: HashMap<DictionaryKey, Encoded>
) : PublicKey(
    CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION, algorithmImplementation, key
) {
    abstract val compactKey: ByteArray

    fun getCompactKeyLength(): Int = getCompactKeyLength(algorithmImplementation)

    @get:Throws(Exception::class)
    open val signaturePublicKey: SignaturePublicKey
        get() {
            return when (algorithmImplementation) {
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519,
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC -> (this as ServerAuthenticationECSdsaPublicKey).signaturePublicKey
                else -> throw Exception("This server authentication public key does not implement signature")
            }
        }

    companion object {
        const val ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC: Byte = 0x00.toByte()
        const val ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519: Byte = 0x01.toByte()

        @JvmStatic
        fun of(
            algorithmImplementation: Byte,
            key: HashMap<DictionaryKey, Encoded>
        ): ServerAuthenticationPublicKey? {
            return when (algorithmImplementation) {
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC -> ServerAuthenticationECSdsaMDCPublicKey(key)
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 -> ServerAuthenticationECSdsaCurve25519PublicKey(key)
                else -> null
            }
        }

        @JvmStatic
        fun getCompactKeyLength(algorithmImplementation: Byte): Int {
            return when (algorithmImplementation) {
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC -> ServerAuthenticationECSdsaMDCPublicKey.COMPACT_KEY_LENGTH
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 -> ServerAuthenticationECSdsaCurve25519PublicKey.COMPACT_KEY_LENGTH
                else -> -1
            }
        }

        @JvmStatic
        @JvmName("ofCompactBytes")
        @Throws(DecodingException::class)
        fun of(compactKeyBytes: ByteArray): ServerAuthenticationPublicKey {
            return when (compactKeyBytes[0]) {
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC -> ServerAuthenticationECSdsaMDCPublicKey.of(compactKeyBytes)
                ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 -> ServerAuthenticationECSdsaCurve25519PublicKey.of(compactKeyBytes)
                else -> throw DecodingException()
            }
        }
    }
}
