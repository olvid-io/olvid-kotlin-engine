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
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.key.symmetric.SymEncCTRAES256Key
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import java.security.InvalidKeyException
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

internal interface SymEnc {
    fun keyByteLength(): Int
    fun ivByteLength(): Int
    fun ciphertextLengthFromPlaintextLength(plaintextLength: Int): Int
    fun plaintextLengthFromCiphertextLength(ciphertextLength: Int): Int

    @Throws(InvalidKeyException::class)
    fun encrypt(iv: ByteArray?, plaintext: ByteArray?, ciphertext: ByteArray?)
    fun decrypt(ciphertext: EncryptedBytes?): ByteArray?

    companion object {
        const val CTR_AES256: String = "ctr-aes-256"
    }
}

internal class KDFDelegateForSymEncCtrAES256 : KDF.Delegate {
    override fun getKeyLength(): Int {
        return SymEncCTRAES256Key.KEY_BYTE_LENGTH
    }

    override fun processBytes(bytes: ByteArray): Array<SymmetricKey> {
        return arrayOf(
            SymEncCTRAES256Key.of(bytes)
        )
    }
}

internal class SymEncCtrAES256(key: SymEncCTRAES256Key) : SymEnc {
    private var aes: Cipher? = null
    private var key: SymEncCTRAES256Key? = null

    init {
        try {
            aes = Cipher.getInstance("AES/CTR/NoPadding")
            this.key = key
        } catch (_: Exception) {
        }
    }

    override fun keyByteLength(): Int {
        return KEY_BYTE_LENGTH
    }

    override fun ivByteLength(): Int {
        return IV_BYTE_LENGTH
    }

    override fun ciphertextLengthFromPlaintextLength(plaintextLength: Int): Int {
        return plaintextLength + IV_BYTE_LENGTH
    }

    override fun plaintextLengthFromCiphertextLength(ciphertextLength: Int): Int {
        return ciphertextLength - IV_BYTE_LENGTH
    }

    @Throws(InvalidKeyException::class)
    override fun encrypt(iv: ByteArray?, plaintext: ByteArray?, ciphertext: ByteArray?) {
        if (iv!!.size != IV_BYTE_LENGTH) {
            throw InvalidKeyException()
        }
        System.arraycopy(iv, 0, ciphertext, 0, IV_BYTE_LENGTH)

        val fullIV = ByteArray(AES_BLOCK_BYTE_LENGTH)
        System.arraycopy(iv, 0, fullIV, 0, IV_BYTE_LENGTH)

        try {
            val cipher = aes!!
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key!!.keyBytes, "AES"),
                IvParameterSpec(fullIV)
            )
            var outOffset: Int = IV_BYTE_LENGTH
            var offsetIn = 0
            while (offsetIn < plaintext!!.size) {
                val len = min(plaintext.size - offsetIn, ENCRYPT_BUFFER_SIZE)
                outOffset += cipher.update(plaintext, offsetIn, len, ciphertext, outOffset)
                offsetIn += ENCRYPT_BUFFER_SIZE
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun decrypt(ciphertext: EncryptedBytes?): ByteArray? {
        val ciphertextBytes = ciphertext!!.getBytes()
        val iv = ciphertextBytes.copyOfRange(0, IV_BYTE_LENGTH)
        val ciphertextEnd = ciphertextBytes.copyOfRange(IV_BYTE_LENGTH, ciphertextBytes.size)
        var plaintext: ByteArray? = null

        val fullIV = ByteArray(AES_BLOCK_BYTE_LENGTH)
        System.arraycopy(iv, 0, fullIV, 0, IV_BYTE_LENGTH)

        try {
            val cipher = aes!!
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key!!.keyBytes, "AES"),
                IvParameterSpec(fullIV)
            )
            plaintext = cipher.doFinal(ciphertextEnd)
        } catch (e: Exception) {
            Logger.x(e)
        }
        return plaintext
    }

    companion object {
        const val KEY_BYTE_LENGTH: Int = 32
        const val IV_BYTE_LENGTH: Int = 8
        const val AES_BLOCK_BYTE_LENGTH: Int = 16

        private const val ENCRYPT_BUFFER_SIZE = 262144
    }
}