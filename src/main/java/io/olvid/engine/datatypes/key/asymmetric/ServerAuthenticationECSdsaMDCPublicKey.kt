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

import io.olvid.engine.crypto.EdwardCurve
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.encoder.EncodingException
import java.util.Arrays


class ServerAuthenticationECSdsaMDCPublicKey(key: HashMap<DictionaryKey, Encoded>) :
    ServerAuthenticationECSdsaPublicKey(
        ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC,
        key,
        SignatureECSdsaMDCPublicKey(key)
    ) {
    companion object {
        val COMPACT_KEY_LENGTH: Int = 1 + Suite.getCurve(EdwardCurve.MDC).byteLength

        @JvmStatic
        @Throws(DecodingException::class)
        fun of(compactKeyBytes: ByteArray): ServerAuthenticationECSdsaMDCPublicKey {
            if ((compactKeyBytes[0] != ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC) || (compactKeyBytes.size != COMPACT_KEY_LENGTH)) {
                throw DecodingException()
            }
            val key = HashMap<DictionaryKey, Encoded>()
            try {
                key.put(
                    DictionaryKey(SignatureECSdsaPublicKey.PUBLIC_Y_COORD_KEY_NAME),
                    Encoded.of(
                        Encoded.bigUIntFromBytes(
                            Arrays.copyOfRange(
                                compactKeyBytes,
                                1,
                                compactKeyBytes.size
                            )
                        ), COMPACT_KEY_LENGTH - 1
                    )
                )
            } catch (_: EncodingException) {
                throw DecodingException()
            }
            return ServerAuthenticationECSdsaMDCPublicKey(key)
        }
    }
}
