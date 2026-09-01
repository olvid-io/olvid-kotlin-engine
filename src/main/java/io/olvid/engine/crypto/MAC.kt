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

import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.symmetric.MACHmacSha256Key
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

interface MAC {
    fun outputLength(): Int

    @Throws(InvalidKeyException::class)
    fun digest(key: MACKey?, bytes: ByteArray?): ByteArray?

    @Throws(InvalidKeyException::class)
    fun digest(key: MACKey?, bytes: ByteArray?, inputLen: Int): ByteArray?

    @Throws(InvalidKeyException::class)
    fun verify(key: MACKey?, bytes: ByteArray?, mac: ByteArray?): Boolean

    fun generateKey(prng: PRNG?): MACKey?

    companion object {
        const val HMAC_SHA256: String = "hmac_sha-256"
    }
}

internal class MACHmacSha256 : MAC {
    override fun outputLength(): Int {
        return OUTPUT_LENGTH
    }

    @Throws(InvalidKeyException::class)
    override fun digest(key: MACKey?, bytes: ByteArray?): ByteArray? {
        try {
            val h = Mac.getInstance("HmacSHA256")
            h.init(SecretKeySpec(key!!.keyBytes, "HmacSHA256"))
            return h.doFinal(bytes)
        } catch (_: NoSuchAlgorithmException) {
        }
        return null
    }

    @Throws(InvalidKeyException::class)
    override fun digest(key: MACKey?, bytes: ByteArray?, inputLen: Int): ByteArray? {
        try {
            val h = Mac.getInstance("HmacSHA256")
            h.init(SecretKeySpec(key!!.keyBytes, "HmacSHA256"))
            h.update(bytes, 0, inputLen)
            return h.doFinal()
        } catch (_: NoSuchAlgorithmException) {
        }
        return null
    }


    @Throws(InvalidKeyException::class)
    override fun verify(key: MACKey?, bytes: ByteArray?, mac: ByteArray?): Boolean {
        val newMac = digest(key, bytes)
        return MessageDigest.isEqual(mac, newMac)
    }

    override fun generateKey(prng: PRNG?): MACKey? {
        val kdf = Suite.getKDF(KDF.KDF_SHA256)
        val kdfSeed = Seed(prng!!)
        try {
            return kdf.gen(kdfSeed, KDFDelegateForHmacSHA256())[0] as MACKey?
        } catch (_: Exception) {
            return null
        }
    }

    companion object {
        const val OUTPUT_LENGTH: Int = 32
    }
}

internal class KDFDelegateForHmacSHA256 : KDF.Delegate {
    override fun getKeyLength(): Int {
        return MACHmacSha256Key.KEY_BYTE_LENGTH
    }

    override fun processBytes(bytes: ByteArray): Array<SymmetricKey> {
        return arrayOf(
            MACHmacSha256Key.of(bytes)
        )
    }
}
