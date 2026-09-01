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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.AuthEnc
import io.olvid.engine.crypto.MAC
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.secure_io.datatypes.Pair
import java.io.IOException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException

class KeyManagerSingleton private constructor() {

    private var seedHandler: SeedHandler? = null

    fun tryToInitKeyManagement(confBaseDir: String, password: String): Boolean {
        return try {
            getInstance().initKeyManagement("$confBaseDir/security", password)
            true
        } catch (e: IOException) {
            Logger.e("Critical error during initKeyManagement, exiting", e)
            false
        } catch (e: NoSuchAlgorithmException) {
            Logger.e("Critical error during initKeyManagement, exiting", e)
            false
        } catch (e: InvalidKeySpecException) {
            Logger.e("Critical error during initKeyManagement, exiting", e)
            false
        } catch (_: InvalidKeyException) {
            false
        } catch (_: DecryptionException) {
            false
        }
    }

    fun getDbEncryptionKey(seedTarget: SeedHandler.EncryptionSeedType): String {
        val appDbEncKeySeed = seedHandler!!.getEncryptionSeed(seedTarget)
        return "x'" + Logger.toHexString(appDbEncKeySeed.getBytes()) + "'"
    }

    fun generateKeyForFileEnc(): AuthEncKey {
        Logger.d("Executing last step in key generation")
        val prng = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)
        val authEnc = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!
        return authEnc.generateKey(prng)!!
    }

    fun generateKeysForFileName(): Pair<MACKey, AuthEncKey>? {
        // first generate MACKey
        val seed = Seed(seedHandler!!.getEncryptionSeed(SeedHandler.EncryptionSeedType.FILE_NAME).getBytes())

        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
        val macHmacSha256 = Suite.getMAC(MAC.HMAC_SHA256)
        if (macHmacSha256 != null) {
            // generate mackey
            val macKey = macHmacSha256.generateKey(prng)
            // generate AuthEncKey
            val authEncKey = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!.generateKey(prng)
            return Pair(macKey!!, authEncKey!!)
        }
        Logger.e("Something went wrong generating key for file Pair<MACKey,AuthEncKey> : ")
        return null
    }

    @Throws(
        IOException::class,
        InvalidKeySpecException::class,
        InvalidKeyException::class,
        NoSuchAlgorithmException::class,
        DecryptionException::class
    )
    private fun initKeyManagement(confBaseDir: String, pwd: String) {
        var password = pwd
        if (password.isEmpty()) {
            password = DEFAULT
        }
        seedHandler = SeedHandler(confBaseDir, password)
    }

    companion object {
        private var keyManagerSingletonInstance: KeyManagerSingleton? = null
        private const val DEFAULT = "unsafe"

        @Synchronized
        @JvmStatic
        fun getInstance(): KeyManagerSingleton {
            if (keyManagerSingletonInstance == null) {
                keyManagerSingletonInstance = KeyManagerSingleton()
            }
            return keyManagerSingletonInstance!!
        }
    }
}
