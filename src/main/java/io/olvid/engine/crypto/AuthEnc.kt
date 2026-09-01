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
import io.olvid.engine.datatypes.key.symmetric.AuthEncAES256ThenSHA256Key
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACHmacSha256Key
import io.olvid.engine.datatypes.key.symmetric.SymEncCTRAES256Key
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import java.security.InvalidKeyException

interface AuthEnc {
    fun keyByteLength(): Int
    fun ciphertextLengthFromPlaintextLength(plaintextLength: Int): Int
    fun plaintextLengthFromCiphertextLength(ciphertextLength: Int): Int

    @Throws(InvalidKeyException::class)
    fun encrypt(key: AuthEncKey?, plaintext: ByteArray?, prng: PRNG?): EncryptedBytes

    @Throws(DecryptionException::class, InvalidKeyException::class)
    fun decrypt(key: AuthEncKey?, ciphertext: EncryptedBytes?): ByteArray?
    fun getKDFDelegate(): KDF.Delegate
    fun generateKey(prng: PRNG?): AuthEncKey?
    fun generateMessageKey(prng: PRNG?, message: ByteArray?): AuthEncKey?
    fun verifyMessageKey(authEncKey: AuthEncKey?, message: ByteArray?): Boolean

    companion object {
        const val CTR_AES256_THEN_HMAC_SHA256: String = "ctr-aes-256_then_hmac_sha-256"
    }
}


internal class KDFDelegateForAuthEncAES256ThenSHA256 : KDF.Delegate {
    override fun getKeyLength(): Int {
        return MACHmacSha256Key.KEY_BYTE_LENGTH + SymEncCTRAES256Key.KEY_BYTE_LENGTH
    }

    override fun processBytes(bytes: ByteArray): Array<SymmetricKey> {
        return arrayOf(
            AuthEncAES256ThenSHA256Key.of(
                bytes.copyOfRange(0, MACHmacSha256Key.KEY_BYTE_LENGTH),
                bytes.copyOfRange(MACHmacSha256Key.KEY_BYTE_LENGTH, MACHmacSha256Key.KEY_BYTE_LENGTH + SymEncCTRAES256Key.KEY_BYTE_LENGTH)
            )
        )
    }
}


internal class AuthEncAES256ThenSHA256 : AuthEnc {
    override fun keyByteLength(): Int {
        return MACHmacSha256Key.KEY_BYTE_LENGTH + SymEncCtrAES256.KEY_BYTE_LENGTH
    }

    override fun ciphertextLengthFromPlaintextLength(plaintextLength: Int): Int {
        return plaintextLength + SymEncCtrAES256.IV_BYTE_LENGTH + MACHmacSha256.OUTPUT_LENGTH
    }

    override fun plaintextLengthFromCiphertextLength(ciphertextLength: Int): Int {
        return ciphertextLength - SymEncCtrAES256.IV_BYTE_LENGTH - MACHmacSha256.OUTPUT_LENGTH
    }

    @Throws(InvalidKeyException::class)
    override fun encrypt(key: AuthEncKey?, plaintext: ByteArray?, prng: PRNG?): EncryptedBytes {
        if (key !is AuthEncAES256ThenSHA256Key) {
            throw InvalidKeyException()
        }
        val macKey = key.macKey
        val encKey = key.encKey
        val mac = MACHmacSha256()
        val enc = SymEncCtrAES256(encKey)

        val ciphertext = ByteArray(ciphertextLengthFromPlaintextLength(plaintext!!.size))
        val iv = prng!!.bytes(SymEncCtrAES256.IV_BYTE_LENGTH)
        enc.encrypt(iv, plaintext, ciphertext)
        val hash =
            mac.digest(macKey, ciphertext, enc.ciphertextLengthFromPlaintextLength(plaintext.size))!!
        System.arraycopy(
            hash,
            0,
            ciphertext,
            enc.ciphertextLengthFromPlaintextLength(plaintext.size),
            hash.size
        )
        return EncryptedBytes(ciphertext)
    }

    @Throws(DecryptionException::class, InvalidKeyException::class)
    override fun decrypt(key: AuthEncKey?, ciphertext: EncryptedBytes?): ByteArray? {
        if (key !is AuthEncAES256ThenSHA256Key) {
            throw InvalidKeyException()
        }
        val macKey = key.macKey
        val encKey = key.encKey
        val mac = MACHmacSha256()
        val enc = SymEncCtrAES256(encKey)

        val ciphertextBytes = ciphertext!!.getBytes()
        val hash = ciphertextBytes.copyOfRange(ciphertextBytes.size - mac.outputLength(), ciphertextBytes.size)
        val encryptedBytes = ciphertextBytes.copyOfRange(0, ciphertextBytes.size - mac.outputLength())
        if (!mac.verify(macKey, encryptedBytes, hash)) {
            throw DecryptionException()
        }
        return enc.decrypt(EncryptedBytes(encryptedBytes))
    }

    override fun getKDFDelegate(): KDF.Delegate {
        return KDFDelegateForAuthEncAES256ThenSHA256()
    }

    override fun generateKey(prng: PRNG?): AuthEncKey? {
        val kdf = Suite.getKDF(KDF.KDF_SHA256)
        val kdfSeed = Seed(prng!!)
        try {
            return kdf.gen(kdfSeed, getKDFDelegate())[0] as AuthEncKey?
        } catch (_: Exception) {
            return null
        }
    }

    override fun generateMessageKey(prng: PRNG?, message: ByteArray?): AuthEncKey {
        val kdf = Suite.getKDF(KDF.KDF_SHA256)

        val encryptionKdfSeed = Seed(prng!!)
        val symEncCTRAES256Key =
            kdf.gen(encryptionKdfSeed, KDFDelegateForSymEncCtrAES256())[0] as SymEncCTRAES256Key

        val concatenation = ByteArray(symEncCTRAES256Key.keyLength + message!!.size)
        System.arraycopy(
            symEncCTRAES256Key.keyBytes,
            0,
            concatenation,
            0,
            symEncCTRAES256Key.keyLength
        )
        System.arraycopy(message, 0, concatenation, symEncCTRAES256Key.keyLength, message.size)
        val hmacSha256Key =
            kdf.gen(Seed(concatenation), KDFDelegateForHmacSHA256())[0] as MACHmacSha256Key

        return AuthEncAES256ThenSHA256Key.of(hmacSha256Key.keyBytes, symEncCTRAES256Key.keyBytes)
    }

    override fun verifyMessageKey(authEncKey: AuthEncKey?, message: ByteArray?): Boolean {
        val kdf = Suite.getKDF(KDF.KDF_SHA256)

        if (authEncKey is AuthEncAES256ThenSHA256Key) {
            val symEncCTRAES256Key = authEncKey.encKey

            val concatenation = ByteArray(symEncCTRAES256Key.keyLength + message!!.size)
            System.arraycopy(
                symEncCTRAES256Key.keyBytes,
                0,
                concatenation,
                0,
                symEncCTRAES256Key.keyLength
            )
            System.arraycopy(message, 0, concatenation, symEncCTRAES256Key.keyLength, message.size)
            val hmacSha256Key =
                kdf.gen(Seed(concatenation), KDFDelegateForHmacSHA256())[0] as MACHmacSha256Key

            return hmacSha256Key.keyBytes.contentEquals(authEncKey.macKey.keyBytes)
        } else {
            return false
        }
    }
}