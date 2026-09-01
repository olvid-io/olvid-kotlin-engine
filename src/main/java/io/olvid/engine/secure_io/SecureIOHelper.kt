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
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.secure_io.datatypes.FileKeys
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.security.InvalidKeyException
import java.util.Arrays

internal object SecureIOHelper {
    const val BLOCK_SIZE: Int = 4096
    const val BLOCK_PAYLOAD_SIZE: Int = 4056
    const val BLOCK_ENCRYPTION_OVERHEAD_SIZE: Int = BLOCK_SIZE - BLOCK_PAYLOAD_SIZE

    val macHmacSha256: MAC = Suite.getMAC(MAC.HMAC_SHA256)!!
    val authEnc: AuthEnc = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!
    val prng: PRNG = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)

    @Throws(IOException::class)
    fun bulletProofRead(fileAccessor: RandomAccessFile, buff: ByteArray): Int {
        return bulletProofRead(fileAccessor, buff, 0, buff.size)
    }

    @Throws(IOException::class)
    fun bulletProofRead(fileAccessor: FileInputStream, buff: ByteArray): Int {
        return bulletProofRead(fileAccessor, buff, 0, buff.size)
    }

    // bullet proof mean to read the exact amount of bytes needed
    @Throws(IOException::class)
    fun bulletProofRead(fileAccessor: RandomAccessFile, buffer: ByteArray, off: Int, len: Int): Int {
        // read until all asked number of bytes are read -- > "bullet proof"
        var bufferFullness = off
        while (bufferFullness < off + len) {
            val count = fileAccessor.read(buffer, bufferFullness, (off + len) - bufferFullness)
            if (count < 0) {
                break
            }
            bufferFullness += count
        }
        return bufferFullness - off
    }

    // bullet proof mean to read the exact amount of bytes needed
    @Throws(IOException::class)
    fun bulletProofRead(fileAccessor: FileInputStream, buffer: ByteArray, off: Int, len: Int): Int {
        // read until all asked number of bytes are read -- > "bullet proof"
        var bufferFullness = off
        while (bufferFullness < off + len) {
            val count = fileAccessor.read(buffer, bufferFullness, (off + len) - bufferFullness)
            if (count < 0) {
                break
            }
            bufferFullness += count
        }
        return bufferFullness - off
    }

    @Throws(IOException::class)
    fun getSecureHeaderEncodedInfosFromFS(fileAccessor: RandomAccessFile): Array<Encoded>? {
        return try {
            val headerBytes = ByteArray(BLOCK_SIZE)
            fileAccessor.seek(0)
            if (bulletProofRead(fileAccessor, headerBytes) != headerBytes.size) {
                throw IOException()
            }
            val encodedHeaderInfo = Encoded.fromLongerByteArray(headerBytes)
            val headerItems = encodedHeaderInfo.decodeList()
            if (headerItems.size == 3) headerItems else null
        } catch (exception: DecodingException) {
            Logger.e("Decoding exception : \n " + exception.message)
            null
        } catch (exception: IllegalArgumentException) {
            Logger.e("Decoding exception : \n " + exception.message)
            null
        }
    }

    @Throws(IOException::class)
    fun getSecureFileHeaderFromFS(
        fileAccessor: RandomAccessFile,
        FSFileName: String,
        check: Boolean
    ): SecureFileHeader? {
        try {
            val associatedKeys = FileKeys(KeyManagerSingleton.getInstance().generateKeysForFileName())
            val headerItems = getSecureHeaderEncodedInfosFromFS(fileAccessor)
            if (headerItems != null) {
                val fileSize = headerItems[0].decodeLong()
                val fileName = headerItems[1].decodeBytes()
                val encFileContentKey = headerItems[2].decodeBytes()
                val plainEncFileContentKey = authEnc.decrypt(
                    associatedKeys.fileNameEncryptionKeys!!.second,
                    EncryptedBytes(encFileContentKey)
                )
                val enc = Encoded(plainEncFileContentKey!!)
                val key = enc.decodeSymmetricKey() as AuthEncKey?
                    ?: throw IOException("Couldn't get content encryption key")

                associatedKeys.fileContentEncryptionKey = key

                val plainFileName = authEnc.decrypt(
                    associatedKeys.fileNameEncryptionKeys!!.second,
                    EncryptedBytes(fileName)
                )

                if (check) {
                    val fileNameMac = macHmacSha256.digest(
                        associatedKeys.fileNameEncryptionKeys!!.first,
                        plainFileName
                    )

                    if (Arrays.equals(fileNameMac, Logger.fromHexString(FSFileName))) {
                        return SecureFileHeader(fileSize, fileName, enc, associatedKeys, plainFileName!!)
                    } else {
                        Logger.e("Mac Mismatch on given file name : \n$FSFileName")
                        throw IOException()
                    }
                } else {
                    return SecureFileHeader(fileSize, fileName, enc, associatedKeys, plainFileName!!)
                }
            } else {
                Logger.e("Couldn't retrieve header from FS : \n$FSFileName")
                return null
            }
        } catch (exception: DecodingException) {
            Logger.e("Decoding error...message --> : \n" + exception.message)
            throw IOException()
        } catch (exception: InvalidKeyException) {
            Logger.e("Bad Key...message --> : \n" + exception.message)
            throw IOException()
        } catch (exception: DecryptionException) {
            Logger.e("Decryption error...message --> : \n" + exception.message)
            throw IOException()
        }
    }

    fun buildFileFromPlainFileName(dir: String?, fileName: String, keys: FileKeys): File? {
        try {
            val digestedFileName = macHmacSha256.digest(
                keys.fileNameEncryptionKeys!!.first,
                fileName.toByteArray()
            )
            return File(dir, Logger.toHexString(digestedFileName!!))
        } catch (exception: InvalidKeyException) {
            Logger.e("Invalid key : \n " + exception.message)
        }
        return null
    }

    fun computeEncryptedDataOffsetFromPlainDataOffset(plainDataOffset: Long): Long {
        val modulo = plainDataOffset % BLOCK_PAYLOAD_SIZE
        return if (modulo > 0) {
            (plainDataOffset / BLOCK_PAYLOAD_SIZE) *
                    BLOCK_SIZE + modulo + BLOCK_ENCRYPTION_OVERHEAD_SIZE + BLOCK_SIZE
        } else {
            (plainDataOffset / BLOCK_PAYLOAD_SIZE) *
                    BLOCK_SIZE + BLOCK_SIZE
        }
    }
}
