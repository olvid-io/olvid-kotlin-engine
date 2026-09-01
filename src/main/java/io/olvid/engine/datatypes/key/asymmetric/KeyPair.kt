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

import io.olvid.engine.datatypes.key.CryptographicKey

open class KeyPair(pub: PublicKey, priv: PrivateKey) {
    @JvmField val publicKey: PublicKey = pub
    @JvmField val privateKey: PrivateKey = priv

    open fun getPublicKey(): PublicKey = publicKey
    open fun getPrivateKey(): PrivateKey = privateKey

    companion object {
        @JvmStatic
        @Throws(Exception::class)
        fun areKeysMatching(publicKey: PublicKey, privateKey: PrivateKey): Boolean {
            if ((publicKey.algorithmClass != privateKey.algorithmClass) ||
                (publicKey.algorithmImplementation != privateKey.algorithmImplementation)) {
                return false
            }

            when (publicKey.algorithmClass) {
                CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION -> {
                    when (publicKey.algorithmImplementation) {
                        ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC ->
                            return ServerAuthenticationECSdsaMDCKeyPair.areKeysMatching(
                                publicKey as ServerAuthenticationECSdsaMDCPublicKey,
                                privateKey as ServerAuthenticationECSdsaMDCPrivateKey
                            )
                        ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 ->
                            return ServerAuthenticationECSdsaCurve25519KeyPair.areKeysMatching(
                                publicKey as ServerAuthenticationECSdsaCurve25519PublicKey,
                                privateKey as ServerAuthenticationECSdsaCurve25519PrivateKey
                            )
                    }
                }
                CryptographicKey.ALGO_CLASS_SIGNATURE -> {
                    // not implemented for signature keys
                }
            }
            throw Exception("Keys match check not implemented")
        }
    }
}
