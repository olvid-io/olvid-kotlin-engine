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
package io.olvid.engine.crypto

import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519PrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519PublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaMDCPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaMDCPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import java.security.InvalidKeyException


interface ServerAuthentication {
    @Throws(InvalidKeyException::class)
    fun solveChallenge(
        challenge: ByteArray,
        privateKey: ServerAuthenticationPrivateKey?,
        publicKey: ServerAuthenticationPublicKey?,
        prng: PRNGService
    ): ByteArray
}

internal abstract class ServerAuthenticationECSdsa(private val signatureECSdsa: SignatureECSdsa) :
    ServerAuthentication {
    @Throws(InvalidKeyException::class)
    fun internalSolveChallenge(
        challenge: ByteArray,
        privateKey: ServerAuthenticationECSdsaPrivateKey,
        publicKey: ServerAuthenticationECSdsaPublicKey,
        prng: PRNGService
    ): ByteArray {
        val padding = prng.bytes(Constants.SIGNATURE_PADDING_LENGTH)
        val formattedChallenge =
            ByteArray(Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX.size + challenge.size + Constants.SIGNATURE_PADDING_LENGTH)
        System.arraycopy(
            Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX,
            0,
            formattedChallenge,
            0,
            Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX.size
        )
        System.arraycopy(
            challenge,
            0,
            formattedChallenge,
            Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX.size,
            challenge.size
        )
        System.arraycopy(
            padding,
            0,
            formattedChallenge,
            Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX.size + challenge.size,
            Constants.SIGNATURE_PADDING_LENGTH
        )
        val signature = signatureECSdsa.sign(
            privateKey.signaturePrivateKey,
            publicKey.signaturePublicKey,
            formattedChallenge,
            prng
        )!!
        val response = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signature.size)
        System.arraycopy(padding, 0, response, 0, Constants.SIGNATURE_PADDING_LENGTH)
        System.arraycopy(signature, 0, response, Constants.SIGNATURE_PADDING_LENGTH, signature.size)
        return response
    }
}


internal class ServerAuthenticationECSdsaMDC : ServerAuthenticationECSdsa(SignatureECSdsaMDC()) {
    @Throws(InvalidKeyException::class)
    override fun solveChallenge(
        challenge: ByteArray,
        privateKey: ServerAuthenticationPrivateKey?,
        publicKey: ServerAuthenticationPublicKey?,
        prng: PRNGService
    ): ByteArray {
        if (publicKey !is ServerAuthenticationECSdsaMDCPublicKey || privateKey !is ServerAuthenticationECSdsaMDCPrivateKey) {
            throw InvalidKeyException()
        }
        return internalSolveChallenge(
            challenge,
            privateKey as ServerAuthenticationECSdsaPrivateKey,
            publicKey as ServerAuthenticationECSdsaPublicKey,
            prng
        )
    }
}


internal class ServerAuthenticationECSdsaCurve25519 :
    ServerAuthenticationECSdsa(SignatureECSdsaCurve25519()) {
    @Throws(InvalidKeyException::class)
    override fun solveChallenge(
        challenge: ByteArray,
        privateKey: ServerAuthenticationPrivateKey?,
        publicKey: ServerAuthenticationPublicKey?,
        prng: PRNGService
    ): ByteArray {
        if (publicKey !is ServerAuthenticationECSdsaCurve25519PublicKey || privateKey !is ServerAuthenticationECSdsaCurve25519PrivateKey) {
            throw InvalidKeyException()
        }
        return internalSolveChallenge(
            challenge,
            privateKey as ServerAuthenticationECSdsaPrivateKey,
            publicKey as ServerAuthenticationECSdsaPublicKey,
            prng
        )
    }
}