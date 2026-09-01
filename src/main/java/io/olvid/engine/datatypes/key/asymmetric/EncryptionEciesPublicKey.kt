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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.encoder.EncodingException
import java.math.BigInteger
import java.security.InvalidParameterException

abstract class EncryptionEciesPublicKey(
    algorithmImplementation: Byte,
    key: HashMap<DictionaryKey, Encoded>
) : EncryptionPublicKey(algorithmImplementation, key) {
    @JvmField val ax: BigInteger?
    @JvmField val ay: BigInteger?

    init {
        try {
            this.ay = key.get(DictionaryKey(PUBLIC_Y_COORD_KEY_NAME))!!.decodeBigUInt()
            val xKey: DictionaryKey = DictionaryKey(PUBLIC_X_COORD_KEY_NAME)
            if (key.containsKey(xKey)) {
                this.ax = key.get(xKey)!!.decodeBigUInt()
            } else {
                this.ax = null
            }
        } catch (_: DecodingException) {
            throw InvalidParameterException()
        }
    }

    override val compactKey: ByteArray
        get() {
            val compactKey = ByteArray(getCompactKeyLength())
            compactKey[0] = algorithmImplementation
            try {
                val yBytes = Encoded.bytesFromBigUInt(
                    key.get(
                        DictionaryKey(EncryptionEciesPublicKey.PUBLIC_Y_COORD_KEY_NAME)
                    )!!.decodeBigUInt(), compactKey.size - 1
                )
                System.arraycopy(yBytes, 0, compactKey, 1, yBytes.size)
            } catch (_: EncodingException) {
            } catch (_: DecodingException) {
            }
            return compactKey
        }

    companion object {
        const val PUBLIC_X_COORD_KEY_NAME: String = "x"
        const val PUBLIC_Y_COORD_KEY_NAME: String = "y"
    }
}
