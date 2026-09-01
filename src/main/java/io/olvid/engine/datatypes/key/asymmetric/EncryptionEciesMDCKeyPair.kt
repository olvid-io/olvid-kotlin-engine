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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EdwardCurvePoint
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.encoder.EncodingException
import java.math.BigInteger


class EncryptionEciesMDCKeyPair(
    publicKey: EncryptionEciesMDCPublicKey,
    privateKey: EncryptionEciesMDCPrivateKey
) : KeyPair(publicKey, privateKey) {
    override fun getPublicKey(): EncryptionEciesMDCPublicKey {
        return publicKey as EncryptionEciesMDCPublicKey
    }

    override fun getPrivateKey(): EncryptionEciesMDCPrivateKey {
        return privateKey as EncryptionEciesMDCPrivateKey
    }

    companion object {
        @JvmStatic
        fun generate(prng: PRNGService): EncryptionEciesMDCKeyPair? {
            val mdc = Suite.getCurve(EdwardCurve.MDC)
            var a: BigInteger
            var A: EdwardCurvePoint
            // check we do not generate a low order public key
            do {
                do {
                    a = prng.bigInt(mdc.q!!)
                } while (a == BigInteger.ZERO || a == BigInteger.ONE)
                A = mdc.scalarMultiplicationWithX(a, mdc.G!!)
            } while (A.isLowOrderPoint())
            val publicKeyDictionary = HashMap<DictionaryKey, Encoded>()
            val privateKeyDictionary = HashMap<DictionaryKey, Encoded>()
            try {
                publicKeyDictionary[DictionaryKey(EncryptionEciesPublicKey.PUBLIC_X_COORD_KEY_NAME)] = Encoded.of(A.X!!, mdc.byteLength)
                publicKeyDictionary[DictionaryKey(EncryptionEciesPublicKey.PUBLIC_Y_COORD_KEY_NAME)] = Encoded.of(A.Y, mdc.byteLength)
                privateKeyDictionary[DictionaryKey(EncryptionEciesPrivateKey.SECRET_EXPONENT_KEY_NAME)] = Encoded.of(a, mdc.byteLength)
            } catch (_: EncodingException) {
                return null
            }
            return EncryptionEciesMDCKeyPair(
                EncryptionEciesMDCPublicKey(publicKeyDictionary),
                EncryptionEciesMDCPrivateKey(privateKeyDictionary)
            )
        }
    }
}
