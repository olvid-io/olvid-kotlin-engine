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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Constants.SignatureContext
import io.olvid.engine.datatypes.Constants.getSignatureChallengePrefix
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EdwardCurvePoint
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.asymmetric.SignatureECSdsaCurve25519PrivateKey
import io.olvid.engine.datatypes.key.asymmetric.SignatureECSdsaCurve25519PublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignatureECSdsaMDCPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.SignatureECSdsaMDCPublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignatureECSdsaPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.SignatureECSdsaPublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignaturePrivateKey
import io.olvid.engine.datatypes.key.asymmetric.SignaturePublicKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.encoder.Encoded.Companion.bigUIntFromBytes
import io.olvid.engine.encoder.Encoded.Companion.bytesFromBigUInt
import io.olvid.engine.encoder.EncodingException
import java.io.ByteArrayOutputStream
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.util.Arrays


abstract class Signature {
    @Throws(InvalidKeyException::class)
    abstract fun sign(
        privateKey: SignaturePrivateKey?,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray?

    @Throws(InvalidKeyException::class)
    abstract fun sign(
        privateKey: SignaturePrivateKey?,
        publicKey: SignaturePublicKey?,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray?

    @Throws(InvalidKeyException::class)
    abstract fun verify(
        publicKey: SignaturePublicKey?,
        message: ByteArray,
        signature: ByteArray
    ): Boolean

    companion object {
        @Throws(Exception::class)
        fun verify(
            signatureContext: SignatureContext,
            identities: Array<out Identity?>,
            signerIdentity: Identity,
            signature: ByteArray
        ): Boolean {
            try {
                val signaturePublicKey =
                    signerIdentity.serverAuthenticationPublicKey.signaturePublicKey

                val baos = ByteArrayOutputStream()
                baos.write(getSignatureChallengePrefix(signatureContext))
                for (identity in identities) {
                    baos.write(identity!!.getBytes())
                }
                baos.write(Arrays.copyOfRange(signature, 0, Constants.SIGNATURE_PADDING_LENGTH))
                val challenge = baos.toByteArray()
                baos.close()

                val signatureAlgo = Suite.getSignature(signaturePublicKey)!!
                return signatureAlgo.verify(
                    signaturePublicKey,
                    challenge,
                    signature.copyOfRange(Constants.SIGNATURE_PADDING_LENGTH, signature.size)
                )
            } catch (e: InvalidKeyException) {
                Logger.x(e)
                return false
            }
        }

        @Throws(Exception::class)
        fun verify(
            signatureContext: SignatureContext,
            deviceUidA: UID,
            deviceUidB: UID,
            identityA: Identity,
            identityB: Identity,
            signerIdentity: Identity,
            signature: ByteArray
        ): Boolean {
            try {
                val signaturePublicKey =
                    signerIdentity.serverAuthenticationPublicKey.signaturePublicKey

                val baos = ByteArrayOutputStream()
                baos.write(getSignatureChallengePrefix(signatureContext))
                baos.write(deviceUidA.bytes)
                baos.write(deviceUidB.bytes)
                baos.write(identityA.getBytes())
                baos.write(identityB.getBytes())
                baos.write(Arrays.copyOfRange(signature, 0, Constants.SIGNATURE_PADDING_LENGTH))
                val challenge = baos.toByteArray()
                baos.close()

                val signatureAlgo = Suite.getSignature(signaturePublicKey)!!
                return signatureAlgo.verify(
                    signaturePublicKey,
                    challenge,
                    Arrays.copyOfRange(
                        signature,
                        Constants.SIGNATURE_PADDING_LENGTH,
                        signature.size
                    )
                )
            } catch (e: InvalidKeyException) {
                Logger.x(e)
                return false
            }
        }

        @Throws(Exception::class)
        fun verify(
            signatureContext: SignatureContext,
            block: ByteArray,
            signerIdentity: Identity,
            signature: ByteArray
        ): Boolean {
            try {
                val signaturePublicKey =
                    signerIdentity.serverAuthenticationPublicKey.signaturePublicKey

                val prefix = getSignatureChallengePrefix(signatureContext)
                val padding = Arrays.copyOfRange(signature, 0, Constants.SIGNATURE_PADDING_LENGTH)
                val challenge =
                    ByteArray(prefix.size + block.size + Constants.SIGNATURE_PADDING_LENGTH)
                System.arraycopy(prefix, 0, challenge, 0, prefix.size)
                System.arraycopy(block, 0, challenge, prefix.size, block.size)
                System.arraycopy(
                    padding,
                    0,
                    challenge,
                    prefix.size + block.size,
                    Constants.SIGNATURE_PADDING_LENGTH
                )

                val signatureAlgo = Suite.getSignature(signaturePublicKey)!!
                return signatureAlgo.verify(
                    signaturePublicKey,
                    challenge,
                    signature.copyOfRange(Constants.SIGNATURE_PADDING_LENGTH, signature.size)
                )
            } catch (e: InvalidKeyException) {
                Logger.x(e)
                return false
            }
        }

        @Throws(Exception::class)
        fun verify(
            signatureContext: SignatureContext,
            groupIdentifier: GroupV2.Identifier,
            nonce: ByteArray?,
            contactIdentity: Identity?,
            signerIdentity: Identity,
            signature: ByteArray
        ): Boolean {
            try {
                val signaturePublicKey =
                    signerIdentity.serverAuthenticationPublicKey.signaturePublicKey

                val baos = ByteArrayOutputStream()
                baos.write(getSignatureChallengePrefix(signatureContext))
                baos.write(groupIdentifier.bytes)
                baos.write(nonce)
                if (contactIdentity != null) {
                    baos.write(contactIdentity.getBytes())
                }
                baos.write(Arrays.copyOfRange(signature, 0, Constants.SIGNATURE_PADDING_LENGTH))
                val challenge = baos.toByteArray()
                baos.close()

                val signatureAlgo = Suite.getSignature(signaturePublicKey)!!
                return signatureAlgo.verify(
                    signaturePublicKey,
                    challenge,
                    signature.copyOfRange(Constants.SIGNATURE_PADDING_LENGTH, signature.size)
                )
            } catch (e: InvalidKeyException) {
                Logger.x(e)
                return false
            }
        }

        fun sign(
            signatureContext: SignatureContext,
            signaturePrivateKey: SignaturePrivateKey?,
            prng: PRNGService
        ): ByteArray? {
            try {
                val prefix = getSignatureChallengePrefix(signatureContext)
                val padding = prng.bytes(Constants.SIGNATURE_PADDING_LENGTH)
                val challenge = ByteArray(prefix.size + Constants.SIGNATURE_PADDING_LENGTH)
                System.arraycopy(prefix, 0, challenge, 0, prefix.size)
                System.arraycopy(
                    padding,
                    0,
                    challenge,
                    prefix.size,
                    Constants.SIGNATURE_PADDING_LENGTH
                )

                val signatureBytes = Suite.getSignature(signaturePrivateKey)!!
                    .sign(signaturePrivateKey, challenge, prng)!!
                val output = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signatureBytes.size)
                System.arraycopy(padding, 0, output, 0, Constants.SIGNATURE_PADDING_LENGTH)
                System.arraycopy(
                    signatureBytes,
                    0,
                    output,
                    Constants.SIGNATURE_PADDING_LENGTH,
                    signatureBytes.size
                )
                return output
            } catch (e: InvalidKeyException) {
                Logger.x(e)
                return null
            }
        }

        fun sign(
            signatureContext: SignatureContext,
            data: ByteArray,
            signaturePrivateKey: SignaturePrivateKey?,
            prng: PRNGService
        ): ByteArray? {
            try {
                val prefix = getSignatureChallengePrefix(signatureContext)
                val padding = prng.bytes(Constants.SIGNATURE_PADDING_LENGTH)
                val challenge =
                    ByteArray(prefix.size + data.size + Constants.SIGNATURE_PADDING_LENGTH)
                System.arraycopy(prefix, 0, challenge, 0, prefix.size)
                System.arraycopy(data, 0, challenge, prefix.size, data.size)
                System.arraycopy(
                    padding,
                    0,
                    challenge,
                    prefix.size + data.size,
                    Constants.SIGNATURE_PADDING_LENGTH
                )

                val signatureBytes = Suite.getSignature(signaturePrivateKey)!!
                    .sign(signaturePrivateKey, challenge, prng)!!
                val output = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signatureBytes.size)
                System.arraycopy(padding, 0, output, 0, Constants.SIGNATURE_PADDING_LENGTH)
                System.arraycopy(
                    signatureBytes,
                    0,
                    output,
                    Constants.SIGNATURE_PADDING_LENGTH,
                    signatureBytes.size
                )
                return output
            } catch (e: InvalidKeyException) {
                Logger.x(e)
                return null
            }
        }
    }
}


internal abstract class SignatureECSdsa(private val curve: EdwardCurve) : Signature() {
    fun internalSign(
        privateKey: SignatureECSdsaPrivateKey,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray? {
        try {
            val A = curve.scalarMultiplicationWithX(privateKey.a!!, curve.G!!)
            val publicKeyDictionary = HashMap<DictionaryKey, Encoded>()
            publicKeyDictionary[DictionaryKey(SignatureECSdsaPublicKey.PUBLIC_X_COORD_KEY_NAME)] = Encoded.of(A.X!!, curve.byteLength)
            publicKeyDictionary[DictionaryKey(SignatureECSdsaPublicKey.PUBLIC_Y_COORD_KEY_NAME)] = Encoded.of(A.Y, curve.byteLength)

            val publicKey: SignatureECSdsaPublicKey = object :
                SignatureECSdsaPublicKey(privateKey.algorithmImplementation, publicKeyDictionary) {}
            return internalSign(privateKey, publicKey, message, prng)
        } catch (_: Exception) {
        }
        return null
    }

    fun internalSign(
        privateKey: SignatureECSdsaPrivateKey,
        publicKey: SignatureECSdsaPublicKey,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray? {
        try {
            val l = curve.byteLength
            val hashInput = ByteArray(message.size + 2 * l)
            val aAndaG = curve.generateRandomScalarAndPoint(prng)
            System.arraycopy(bytesFromBigUInt(aAndaG.point!!.Y, l), 0, hashInput, 0, l)
            System.arraycopy(Encoded.bytesFromBigUInt(publicKey.ay!!, l), 0, hashInput, l, l)
            System.arraycopy(message, 0, hashInput, 2 * l, message.size)

            // TODO: switch to this once all clients support signature with SHA512 hash (supported since build 242, 2024-06-10)
//            byte[] hash = new HashSHA512().digest(hashInput);
            val hash = HashSHA256().digest(hashInput)
            val e = bigUIntFromBytes(hash)
            val y = aAndaG.scalar!!.subtract(privateKey.a!!.multiply(e)).mod(curve.q)

            val signature = ByteArray(hash.size + l)
            System.arraycopy(hash, 0, signature, 0, hash.size)
            System.arraycopy(bytesFromBigUInt(y, l), 0, signature, hash.size, l)
            return signature
        } catch (_: EncodingException) {
        }
        return null
    }

    fun internalVerify(
        publicKey: SignatureECSdsaPublicKey,
        message: ByteArray,
        signature: ByteArray
    ): Boolean {
        try {
            val l = curve.byteLength
            // Our verification supports both hash with SHA256 (legacy) and SHA512
            val isSha512: Boolean
            if (signature.size == HashSHA256.OUTPUT_LENGTH + l) {
                isSha512 = false
            } else if (signature.size == HashSHA512.OUTPUT_LENGTH + l) {
                isSha512 = true
            } else {
                return false
            }
            val A = EdwardCurvePoint.noCheckFactory(publicKey.ax, publicKey.ay!!, curve)

            // check that the public key A is not a low order point
            if (A.isLowOrderPoint()) {
                return false
            }

            val hash = Arrays.copyOfRange(signature, 0, signature.size - l)
            val e = bigUIntFromBytes(hash)
            val y =
                bigUIntFromBytes(Arrays.copyOfRange(signature, signature.size - l, signature.size))
            // check that the signature y is indeed smaller than q (to prevent undetected signature reuse)
            if (y.compareTo(curve.q) >= 0) {
                return false
            }
            val points = curve.mulAdd(y, curve.G!!, e, A)

            val hashInput = ByteArray(message.size + 2 * l)
            System.arraycopy(Encoded.bytesFromBigUInt(publicKey.ay, l), 0, hashInput, l, l)
            System.arraycopy(message, 0, hashInput, 2 * l, message.size)

            var found = false
            for (point in points) {
                System.arraycopy(bytesFromBigUInt(point!!.Y, l), 0, hashInput, 0, l)
                val recomputedHash =
                    if (isSha512) HashSHA512().digest(hashInput) else HashSHA256().digest(hashInput)

                if (MessageDigest.isEqual(hash, recomputedHash)) {
                    found = true
                }
            }
            return found
        } catch (_: EncodingException) {
        }
        return false
    }
}

internal class SignatureECSdsaMDC : SignatureECSdsa(MDC.instance) {
    @Throws(InvalidKeyException::class)
    override fun sign(
        privateKey: SignaturePrivateKey?,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray? {
        if (privateKey !is SignatureECSdsaMDCPrivateKey) {
            throw InvalidKeyException()
        }
        return internalSign(privateKey, message, prng)
    }


    @Throws(InvalidKeyException::class)
    override fun sign(
        privateKey: SignaturePrivateKey?,
        publicKey: SignaturePublicKey?,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray? {
        if (privateKey !is SignatureECSdsaMDCPrivateKey) {
            throw InvalidKeyException()
        }
        return internalSign(
            privateKey as SignatureECSdsaPrivateKey,
            (publicKey as SignatureECSdsaPublicKey?)!!,
            message,
            prng
        )
    }

    @Throws(InvalidKeyException::class)
    override fun verify(
        publicKey: SignaturePublicKey?,
        message: ByteArray,
        signature: ByteArray
    ): Boolean {
        if (publicKey !is SignatureECSdsaMDCPublicKey) {
            throw InvalidKeyException()
        }
        return internalVerify(publicKey as SignatureECSdsaPublicKey, message, signature)
    }
}

internal class SignatureECSdsaCurve25519 : SignatureECSdsa(Curve25519.instance) {
    @Throws(InvalidKeyException::class)
    override fun sign(
        privateKey: SignaturePrivateKey?,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray? {
        if (privateKey !is SignatureECSdsaCurve25519PrivateKey) {
            throw InvalidKeyException()
        }
        return internalSign(privateKey as SignatureECSdsaPrivateKey, message, prng)
    }

    @Throws(InvalidKeyException::class)
    override fun sign(
        privateKey: SignaturePrivateKey?,
        publicKey: SignaturePublicKey?,
        message: ByteArray,
        prng: PRNGService
    ): ByteArray? {
        if (privateKey !is SignatureECSdsaCurve25519PrivateKey) {
            throw InvalidKeyException()
        }
        return internalSign(
            privateKey as SignatureECSdsaPrivateKey,
            (publicKey as SignatureECSdsaPublicKey?)!!,
            message,
            prng
        )
    }

    @Throws(InvalidKeyException::class)
    override fun verify(
        publicKey: SignaturePublicKey?,
        message: ByteArray,
        signature: ByteArray
    ): Boolean {
        if (publicKey !is SignatureECSdsaCurve25519PublicKey) {
            throw InvalidKeyException()
        }
        return internalVerify(publicKey as SignatureECSdsaPublicKey, message, signature)
    }
}