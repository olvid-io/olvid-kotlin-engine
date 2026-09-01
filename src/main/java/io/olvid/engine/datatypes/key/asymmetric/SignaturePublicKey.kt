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
import io.olvid.engine.datatypes.key.CryptographicKey
import io.olvid.engine.encoder.Encoded
import java.util.HashMap

abstract class SignaturePublicKey(
    algorithmImplementation: Byte,
    key: HashMap<DictionaryKey, Encoded>
) : PublicKey(
    CryptographicKey.ALGO_CLASS_SIGNATURE, algorithmImplementation, key
) {
    protected val curve: EdwardCurve?
        get() {
            return when (algorithmImplementation) {
                ALGO_IMPL_EC_SDSA_MDC -> Suite.getCurve(EdwardCurve.MDC)
                ALGO_IMPL_EC_SDSA_CURVE25519 -> Suite.getCurve(EdwardCurve.CURVE_25519)
                else -> null
            }
        }

    companion object {
        const val ALGO_IMPL_EC_SDSA_MDC: Byte = 0x00.toByte()
        const val ALGO_IMPL_EC_SDSA_CURVE25519: Byte = 0x01.toByte()

        @JvmStatic
        fun of(algorithmImplementation: Byte, key: HashMap<DictionaryKey, Encoded>): SignaturePublicKey? {
            return when (algorithmImplementation) {
                ALGO_IMPL_EC_SDSA_MDC -> SignatureECSdsaMDCPublicKey(key)
                ALGO_IMPL_EC_SDSA_CURVE25519 -> SignatureECSdsaCurve25519PublicKey(key)
                else -> null
            }
        }
    }
}
