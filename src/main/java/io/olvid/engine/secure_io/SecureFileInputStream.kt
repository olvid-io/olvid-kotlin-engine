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
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.storage.EngineInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.RandomAccessFile
import java.security.InvalidKeyException

class SecureFileInputStream(associatedFile: SecureFile?) : EngineInputStream() {

    private val associatedSecureFile: SecureFile
    private var FSReadPosition: Long = SecureIOHelper.BLOCK_SIZE.toLong()
    private val secureFileHeader: SecureFileHeader
    private val fileAccessor: RandomAccessFile
    private var plainTxtReadPosition: Long = 0
    private lateinit var blockPlainTxt: ByteArray
    private var fileReadNeeded = true

    init {
        val fsFile = associatedFile?.fsNameFile ?: throw RuntimeException()
        if (!fsFile.exists()) {
            throw FileNotFoundException()
        }
        associatedSecureFile = associatedFile
        fileAccessor = RandomAccessFile(fsFile, "r")
        secureFileHeader = SecureIOHelper.getSecureFileHeaderFromFS(fileAccessor, fsFile.name, false)
            ?: throw RuntimeException()
    }

    @Throws(IOException::class)
    override fun read(): Int {
        val bytes = ByteArray(1)
        if (read(bytes, 0, 1) == 1) {
            return bytes[0].toInt() and 0xFF
        }
        return -1
    }

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        var off = off
        var len = len
        if (len == 0) {
            Logger.d("Nothing to read....or inconsistent args?\ngiven length : $len")
            return 0
        }
        if (off > b.size) {
            Logger.w(
                "destination offset is inconsistent with output byte array length\n" +
                        "given off : " + off + "given output byte length." + b.size
            )
            return 0
        }
        // already reached EOF
        if (FSReadPosition >= fileAccessor.length() - 1 && plainTxtReadPosition == secureFileHeader.fileSize) {
            return -1
        }
        // asked length greater number of bytes already read,
        // we set it to the number of bytes already read index
        if (len > secureFileHeader.fileSize - plainTxtReadPosition) {
            len = (secureFileHeader.fileSize - plainTxtReadPosition).toInt()
        }
        // check if len goes beyond b length taking into account the given offset
        if (b.size - off < len) {
            len = b.size - off
        }

        val originalLen = len
        var readBuffer = ByteArray(SecureIOHelper.BLOCK_SIZE)
        var plainTxtBlockOffset = (plainTxtReadPosition % SecureIOHelper.BLOCK_PAYLOAD_SIZE).toInt()
        fileAccessor.seek(FSReadPosition)
        // decryption loop
        while (len > 0) {
            try {
                // Mid block read
                if (FSReadPosition + SecureIOHelper.BLOCK_SIZE >= fileAccessor.length()) { // reached last encrypted block
                    readBuffer = ByteArray((fileAccessor.length() - FSReadPosition).toInt())
                }
                if (fileReadNeeded) { // new block needs to be read
                    if (SecureIOHelper.bulletProofRead(fileAccessor, readBuffer) != readBuffer.size) {
                        throw IOException()
                    }

                    blockPlainTxt = SecureIOHelper.authEnc.decrypt(
                        secureFileHeader.associatedKeys.fileContentEncryptionKey,
                        EncryptedBytes(readBuffer)
                    )!!
                    fileReadNeeded = false
                    FSReadPosition += SecureIOHelper.authEnc.ciphertextLengthFromPlaintextLength(blockPlainTxt.size)
                }
                val bytesToRead = Math.min(blockPlainTxt.size - plainTxtBlockOffset, len)
                System.arraycopy(blockPlainTxt, plainTxtBlockOffset, b, off, bytesToRead)
                plainTxtBlockOffset = 0
                plainTxtReadPosition += bytesToRead
                fileReadNeeded = (plainTxtReadPosition % SecureIOHelper.BLOCK_PAYLOAD_SIZE == 0L)
                len -= bytesToRead
                off += bytesToRead
            } catch (e: DecryptionException) {
                Logger.e("Decryption Exception : \n" + e.message, e)
                throw IOException()
            } catch (e: InvalidKeyException) {
                Logger.e("Invalid Key : \n" + e.message)
                throw IOException()
            }
        }
        return originalLen
    }

    @Throws(IOException::class)
    override fun seek(index: Long) {
        if (index in 0 until secureFileHeader.fileSize) {
            plainTxtReadPosition = index
            FSReadPosition = (index / SecureIOHelper.BLOCK_PAYLOAD_SIZE) *
                    SecureIOHelper.BLOCK_SIZE + SecureIOHelper.BLOCK_SIZE
            fileReadNeeded = true
        } else {
            throw IOException("seek index cannot be negative or greater than file size, given index value : $index")
        }
    }

    @Throws(IOException::class)
    override fun close() {
        fileAccessor.close()
    }
}
