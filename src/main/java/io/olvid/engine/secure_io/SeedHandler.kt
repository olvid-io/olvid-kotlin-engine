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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.secure_io.datatypes.Pair
import java.io.IOException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException

class SeedHandler @Throws(
    NoSuchAlgorithmException::class,
    InvalidKeySpecException::class,
    IOException::class,
    DecryptionException::class,
    InvalidKeyException::class
) constructor(confBaseDir: String, userSecret: String) {

    enum class EncryptionSeedType {
        ENGINE_DATABASE,
        APP_DATABASE,
        FILE_NAME,
        FILE_CONTENT
    }

    private val propsHelper: PropertiesHelper = PropertiesHelper(confBaseDir, PROPS_FILE, userSecret)

    internal fun getEncryptionSeed(encryptionSeedType: EncryptionSeedType): Seed {
        // get seed from file
        return when (encryptionSeedType) {
            EncryptionSeedType.ENGINE_DATABASE -> getSeed(ENGINE_DATABASE_ID)
            EncryptionSeedType.APP_DATABASE -> getSeed(APP_DATABASE_ID)
            EncryptionSeedType.FILE_NAME -> getSeed(FILE_ENCRYPTION_ID)
            else -> throw IllegalStateException("Unexpected value: $encryptionSeedType")
        }
    }

    /**
     * Gets the corresponding seed, creates it if it does not exist.
     * @param propId the property id of the seed
     * @return the Seed for key generation
     */
    private fun getSeed(propId: String): Seed {
        val hex = propsHelper.props.getProperty(propId)
        return if (hex == null) {
            // generate seed
            val fileNameEncSeed = Seed(Suite.getDefaultPRNGService(0))
            // save to property file
            try {
                propsHelper.addProp(Pair(propId, Logger.toHexString(fileNameEncSeed.getBytes())))
            } catch (e: DecryptionException) {
                e.printStackTrace()
            } catch (e: InvalidKeyException) {
                e.printStackTrace()
            } catch (e: IOException) {
                e.printStackTrace()
            }
            fileNameEncSeed
        } else {
            Seed(Logger.fromHexString(hex))
        }
    }

    companion object {
        private const val PROPS_FILE = "seeds.properties"
        private const val ENGINE_DATABASE_ID = "engine_database_id"
        private const val APP_DATABASE_ID = "app_database_id"
        private const val FILE_ENCRYPTION_ID = "file_encryption_id"
    }
}
