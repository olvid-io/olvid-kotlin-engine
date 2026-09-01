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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.secure_io.datatypes.FileKeys
import java.security.InvalidKeyException

class SecureFileHeader(
    var fileSize: Long,
    var encryptedFileName: ByteArray,
    private val contentEncryptionFileKey: Encoded,
    val associatedKeys: FileKeys,
    val plainFileName: ByteArray
) {
    fun buildHeaderBlock(fileNameAuthEncKey: AuthEncKey): ByteArray? {
        try {
            // Encrypt content key
            val encryptedKey = SecureIOHelper.authEnc.encrypt(
                fileNameAuthEncKey,
                contentEncryptionFileKey.bytes,
                Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)
            )
            val encodedList = Encoded.of(
                arrayOf(
                    Encoded.of(fileSize),
                    Encoded.of(encryptedFileName),
                    Encoded.of(encryptedKey)
                )
            )
            val headerToWrite = ByteArray(SecureIOHelper.BLOCK_SIZE)
            System.arraycopy(encodedList.bytes, 0, headerToWrite, 0, encodedList.bytes.size)
            return headerToWrite
        } catch (invalidKeyException: InvalidKeyException) {
            Logger.e("Invalid Key Exception : \n" + invalidKeyException.message, invalidKeyException)
        }
        return null
    }
}
