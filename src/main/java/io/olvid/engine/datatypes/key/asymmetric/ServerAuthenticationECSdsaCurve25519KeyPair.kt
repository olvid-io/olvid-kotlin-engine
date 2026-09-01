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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EdwardCurvePoint
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.encoder.EncodingException
import java.math.BigInteger


class ServerAuthenticationECSdsaCurve25519KeyPair(
    publicKey: ServerAuthenticationECSdsaCurve25519PublicKey,
    privateKey: ServerAuthenticationECSdsaCurve25519PrivateKey
) : KeyPair(publicKey, privateKey) {
    override fun getPublicKey(): ServerAuthenticationECSdsaCurve25519PublicKey {
        return publicKey as ServerAuthenticationECSdsaCurve25519PublicKey
    }

    override fun getPrivateKey(): ServerAuthenticationECSdsaCurve25519PrivateKey {
        return privateKey as ServerAuthenticationECSdsaCurve25519PrivateKey
    }

    companion object {
        @JvmStatic
        fun generate(prng: PRNG): ServerAuthenticationECSdsaCurve25519KeyPair {
            val curve25519 = Suite.getCurve(EdwardCurve.CURVE_25519)
            var a: BigInteger
            var A: EdwardCurvePoint
            // check we do not generate a low order public key
            do {
                do {
                    a = prng.bigInt(curve25519.q!!)
                } while (a == BigInteger.ZERO || a == BigInteger.ONE)
                A = curve25519.scalarMultiplicationWithX(a, curve25519.G!!)
            } while (A.isLowOrderPoint())
            val publicKeyDictionary = HashMap<DictionaryKey, Encoded>()
            val privateKeyDictionary = HashMap<DictionaryKey, Encoded>()
            try {
                publicKeyDictionary[DictionaryKey(ServerAuthenticationECSdsaPublicKey.PUBLIC_X_COORD_KEY_NAME)] = Encoded.of(A.X!!, curve25519.byteLength)
                publicKeyDictionary[DictionaryKey(ServerAuthenticationECSdsaPublicKey.PUBLIC_Y_COORD_KEY_NAME)] = Encoded.of(A.Y, curve25519.byteLength)
                privateKeyDictionary[DictionaryKey(ServerAuthenticationECSdsaPrivateKey.SECRET_EXPONENT_KEY_NAME)] = Encoded.of(a, curve25519.byteLength)
            } catch (e: EncodingException) {
                throw RuntimeException("Failed to encode key", e)
            }
            return ServerAuthenticationECSdsaCurve25519KeyPair(
                ServerAuthenticationECSdsaCurve25519PublicKey(publicKeyDictionary),
                ServerAuthenticationECSdsaCurve25519PrivateKey(privateKeyDictionary)
            )
        }

        fun areKeysMatching(
            publicKey: ServerAuthenticationECSdsaCurve25519PublicKey,
            privateKey: ServerAuthenticationECSdsaCurve25519PrivateKey
        ): Boolean {
            val curve25519 = Suite.getCurve(EdwardCurve.CURVE_25519)
            val A = curve25519.scalarMultiplicationWithX(
                privateKey.signaturePrivateKey.a!!,
                curve25519.G!!
            )
            return A.Y == publicKey.signaturePublicKey.ay
        }
    }
}
