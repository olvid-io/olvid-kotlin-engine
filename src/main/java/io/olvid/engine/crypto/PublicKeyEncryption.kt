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

import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.containers.CiphertextAndKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519PrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519PublicKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesMDCPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesMDCPublicKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesPublicKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded.Companion.bigUIntFromBytes
import io.olvid.engine.encoder.Encoded.Companion.bytesFromBigUInt
import io.olvid.engine.encoder.EncodingException
import java.math.BigInteger
import java.security.InvalidKeyException
import java.util.Arrays

interface PublicKeyEncryption {
    @Throws(InvalidKeyException::class)
    fun encrypt(
        publicKey: EncryptionPublicKey?,
        plaintext: ByteArray?,
        prng: PRNGService?
    ): EncryptedBytes?

    @Throws(InvalidKeyException::class, DecryptionException::class)
    fun decrypt(privateKey: EncryptionPrivateKey?, ciphertext: EncryptedBytes?): ByteArray?

    @Throws(InvalidKeyException::class)
    fun kemEncrypt(publicKey: EncryptionPublicKey?, prng: PRNGService?): CiphertextAndKey?


    @Throws(InvalidKeyException::class, DecryptionException::class)
    fun kemDecrypt(privateKey: EncryptionPrivateKey?, ciphertext: EncryptedBytes?): AuthEncKey?
}

internal abstract class PublicKeyEncryptionEcies protected constructor(private val kem: KemEcies256Kem512) :
    PublicKeyEncryption {
    private val dem: AuthEncAES256ThenSHA256

    init {
        this.dem = AuthEncAES256ThenSHA256()
    }

    @Throws(InvalidKeyException::class)
    override fun encrypt(
        publicKey: EncryptionPublicKey?,
        plaintext: ByteArray?,
        prng: PRNGService?
    ): EncryptedBytes? {
        val ciphertextBytes =
            ByteArray(kem.ciphertextLength() + dem.ciphertextLengthFromPlaintextLength(plaintext!!.size))

        val ciphertextAndKey = kem.encrypt(publicKey, prng)!!
        System.arraycopy(
            ciphertextAndKey.getCiphertext()!!.getBytes(),
            0,
            ciphertextBytes,
            0,
            kem.ciphertextLength()
        )

        val demCiphertext = dem.encrypt(ciphertextAndKey.getKey(), plaintext, prng)
        System.arraycopy(
            demCiphertext.getBytes(),
            0,
            ciphertextBytes,
            kem.ciphertextLength(),
            dem.ciphertextLengthFromPlaintextLength(plaintext.size)
        )

        return EncryptedBytes(ciphertextBytes)
    }

    @Throws(InvalidKeyException::class, DecryptionException::class)
    override fun decrypt(
        privateKey: EncryptionPrivateKey?,
        ciphertext: EncryptedBytes?
    ): ByteArray? {
        val ciphertextBytes = ciphertext!!.getBytes()
        val kemCiphertext = ciphertext.getBytes().copyOfRange(0, KemEcies256Kem512.CIPHERTEXT_LENGTH)
        val key = kem.decrypt(privateKey, kemCiphertext)

        val demCiphertext = EncryptedBytes(
            ciphertext.getBytes().copyOfRange(KemEcies256Kem512.CIPHERTEXT_LENGTH, ciphertextBytes.size)
        )
        return dem.decrypt(key, demCiphertext)
    }

    @Throws(InvalidKeyException::class)
    override fun kemEncrypt(publicKey: EncryptionPublicKey?, prng: PRNGService?): CiphertextAndKey? {
        return kem.encrypt(publicKey, prng)
    }

    @Throws(InvalidKeyException::class, DecryptionException::class)
    override fun kemDecrypt(
        privateKey: EncryptionPrivateKey?,
        ciphertext: EncryptedBytes?
    ): AuthEncKey? {
        if (ciphertext!!.length != KemEcies256Kem512.CIPHERTEXT_LENGTH) {
            throw DecryptionException("Bad kem ciphertext length")
        }
        return kem.decrypt(privateKey, ciphertext.getBytes())
    }
}

internal class PublicKeyEncryptionEciesMDC : PublicKeyEncryptionEcies(KemEcies256Kem512MDC())

internal class PublicKeyEncryptionEciesCurve25519 :
    PublicKeyEncryptionEcies(KemEcies256Kem512Curve25519())


internal interface KEM {
    @Throws(InvalidKeyException::class)
    fun encrypt(publicKey: EncryptionPublicKey?, prng: PRNGService?): CiphertextAndKey?

    @Throws(InvalidKeyException::class)
    fun decrypt(privateKey: EncryptionPrivateKey?, ciphertext: ByteArray?): AuthEncKey?
    fun ciphertextLength(): Int
}

internal abstract class KemEcies256Kem512 protected constructor(private val curve: EdwardCurve) :
    KEM {
    fun internalEncrypt(publicKey: EncryptionPublicKey, prng: PRNGService): CiphertextAndKey? {
        val Ay = (publicKey as EncryptionEciesPublicKey).ay
        // check that the Ay public key is not a low order point
        if (curve.isLowOrderPoint(Ay!!)) {
            return null
        }
        val l = curve.byteLength
        var r: BigInteger
        do {
            r = prng.bigInt(curve.q!!)
        } while (r == BigInteger.ZERO)
        val Gy = curve.G!!.Y
        val By = curve.scalarMultiplication(r, Gy)
        val Dy = curve.scalarMultiplication(r, Ay)
        try {
            val ciphertext = bytesFromBigUInt(By, l)
            val seedBytes = ByteArray(2 * l)
            System.arraycopy(ciphertext, 0, seedBytes, 0, l)
            System.arraycopy(bytesFromBigUInt(Dy, l), 0, seedBytes, l, l)
            val key = KDFSha256().gen(
                Seed(seedBytes),
                KDFDelegateForAuthEncAES256ThenSHA256()
            )[0] as AuthEncKey?
            return CiphertextAndKey(key, EncryptedBytes(ciphertext))
        } catch (_: EncodingException) {
            return null
        }
    }

    fun internalDecrypt(privateKey: EncryptionPrivateKey, c: ByteArray): AuthEncKey? {
        var a = (privateKey as EncryptionEciesPrivateKey).a
        val l = curve.byteLength
        if (c.size != l) {
            return null
        }
        var By = bigUIntFromBytes(c)
        By = curve.scalarMultiplication(curve.nu!!, By)
        if (By == BigInteger.ONE) {
            return null
        }
        a = a!!.multiply(curve.nuInv).mod(curve.q)
        val Dy = curve.scalarMultiplication(a, By)
        try {
            val seedBytes = ByteArray(2 * l)
            System.arraycopy(c, 0, seedBytes, 0, l)
            System.arraycopy(bytesFromBigUInt(Dy, l), 0, seedBytes, l, l)
            return KDFSha256().gen(
                Seed(seedBytes),
                KDFDelegateForAuthEncAES256ThenSHA256()
            )[0] as AuthEncKey?
        } catch (_: EncodingException) {
            return null
        }
    }

    override fun ciphertextLength(): Int {
        return CIPHERTEXT_LENGTH
    }

    companion object {
        const val CIPHERTEXT_LENGTH: Int = 32
    }
}

internal class KemEcies256Kem512MDC : KemEcies256Kem512(MDC.instance) {
    @Throws(InvalidKeyException::class)
    override fun encrypt(publicKey: EncryptionPublicKey?, prng: PRNGService?): CiphertextAndKey? {
        if (publicKey !is EncryptionEciesMDCPublicKey) {
            throw InvalidKeyException()
        }
        return internalEncrypt(publicKey, prng!!)
    }

    @Throws(InvalidKeyException::class)
    override fun decrypt(privateKey: EncryptionPrivateKey?, ciphertext: ByteArray?): AuthEncKey? {
        if (privateKey !is EncryptionEciesMDCPrivateKey) {
            throw InvalidKeyException()
        }
        return internalDecrypt(privateKey, ciphertext!!)
    }
}

internal class KemEcies256Kem512Curve25519 : KemEcies256Kem512(Curve25519.instance) {
    @Throws(InvalidKeyException::class)
    override fun encrypt(publicKey: EncryptionPublicKey?, prng: PRNGService?): CiphertextAndKey? {
        if (publicKey !is EncryptionEciesCurve25519PublicKey) {
            throw InvalidKeyException()
        }
        return internalEncrypt(publicKey, prng!!)
    }

    @Throws(InvalidKeyException::class)
    override fun decrypt(privateKey: EncryptionPrivateKey?, ciphertext: ByteArray?): AuthEncKey? {
        if (privateKey !is EncryptionEciesCurve25519PrivateKey) {
            throw InvalidKeyException()
        }
        return internalDecrypt(privateKey, ciphertext!!)
    }
}