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

package io.olvid.engine.secure_io

import io.olvid.engine.crypto.AuthEnc.Companion.CTR_AES256_THEN_HMAC_SHA256
import io.olvid.engine.crypto.PRNG.Companion.PRNG_HMAC_SHA256
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.secure_io.datatypes.Pair
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.util.Properties
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class PropertiesHelper @Throws(
    IOException::class,
    InvalidKeySpecException::class,
    NoSuchAlgorithmException::class,
    DecryptionException::class,
    InvalidKeyException::class
) constructor(confBaseDir: String, fileLocation: String, userSecret: String) {

    val props: Properties = Properties()
    private val ourFile: File
    private var userSecretSeed: ByteArray? = null
    private var salt = ByteArray(16)

    init {
        val dir = File(confBaseDir)
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                throw IOException("Couldn't create props dir")
            }
            ourFile = File(dir, fileLocation)
            if (!ourFile.createNewFile()) {
                throw IOException("Couldn't create key props file")
            }
            val pwd = userSecret.toCharArray()
            salt = Suite.getPRNGService(PRNG_HMAC_SHA256).bytes(16)
            val spec = PBEKeySpec(pwd, salt, 10000, 256)
            val secretKeyFactory = SecretKeyFactory.getInstance(PWD_HASH_METHOD)
            userSecretSeed = secretKeyFactory.generateSecret(spec).encoded
        } else {
            ourFile = File(dir, fileLocation)
            readSecuredProperties(userSecret)
        }
    }

    @Throws(DecryptionException::class, IOException::class, InvalidKeyException::class)
    fun addProp(prop: Pair<String, String>?) {
        if (prop != null) {
            props.setProperty(prop.first, prop.second)
            commitChanges()
        }
    }

    @Throws(IOException::class)
    private fun readProperties(fileContent: InputStream) {
        props.load(fileContent)
    }

    @Throws(
        IOException::class,
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        DecryptionException::class,
        InvalidKeyException::class
    )
    private fun readSecuredProperties(userSecret: String?) {
        if (userSecret != null && userSecret.isNotEmpty()) {
            FileInputStream(ourFile.path).use { fis ->
                SecureIOHelper.bulletProofRead(fis, salt)
                val pwd = userSecret.toCharArray()
                val spec = PBEKeySpec(pwd, salt, 10000, 256)
                val secretKeyFactory = SecretKeyFactory.getInstance(PWD_HASH_METHOD)
                userSecretSeed = secretKeyFactory.generateSecret(spec).encoded
                val encKey = Suite.getAuthEnc(CTR_AES256_THEN_HMAC_SHA256)!!
                    .generateKey(Suite.getPRNG(PRNG_HMAC_SHA256, Seed(userSecretSeed!!)))
                if (fis.channel.size() > 0) {
                    val encData = ByteArray((fis.channel.size() - 16).toInt())
                    SecureIOHelper.bulletProofRead(fis, encData)
                    val clearText = Suite.getAuthEnc(CTR_AES256_THEN_HMAC_SHA256)!!
                        .decrypt(encKey, EncryptedBytes(encData))
                    val bais = ByteArrayInputStream(clearText!!)
                    readProperties(bais)
                }
            }
        }
    }

    @Throws(IOException::class, InvalidKeyException::class)
    private fun commitChanges() {
        FileOutputStream(ourFile.path).use { os ->
            val baos = ByteArrayOutputStream()
            props.store(baos, null)
            if (userSecretSeed != null) {
                val encKey = Suite.getAuthEnc(CTR_AES256_THEN_HMAC_SHA256)!!
                    .generateKey(Suite.getPRNG(PRNG_HMAC_SHA256, Seed(userSecretSeed!!)))
                val encBytes = Suite.getAuthEnc(CTR_AES256_THEN_HMAC_SHA256)!!
                    .encrypt(encKey, baos.toByteArray(), Suite.getPRNG(PRNG_HMAC_SHA256, Seed(userSecretSeed!!)))
                baos.reset()
                baos.write(salt)
                baos.write(encBytes.bytes)
            }
            os.write(baos.toByteArray())
            baos.close()
        }
    }

    companion object {
        private const val PWD_HASH_METHOD = "PBKDF2WithHmacSHA512"
    }
}
