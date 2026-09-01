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
import io.olvid.engine.encoder.Encoded
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.util.Arrays

class SecureFileOutputStream @Throws(IOException::class) constructor(
    secureFile: SecureFile?,
    private val accessMode: AccessMode,
    truncationOffset: Long
) : OutputStream() {

    enum class AccessMode {
        TRUNCATE,
        APPEND,
    }

    var secureFileHeader: SecureFileHeader? = null
        private set
    private val secureFile: SecureFile
    private val blockBuffer: ByteArray
    private var blockBufferFullness: Int
    private var lastByteWrittenPosition: Long
    private lateinit var fileAccessor: RandomAccessFile

    init {
        if (secureFile == null) {
            throw IOException()
        }
        if (secureFile.isDirectory) {
            Logger.e("Can't open secure output stream on directory")
            throw IOException()
        }
        this.lastByteWrittenPosition = SecureIOHelper.BLOCK_SIZE.toLong()
        this.blockBuffer = ByteArray(SecureIOHelper.BLOCK_PAYLOAD_SIZE)
        this.blockBufferFullness = 0
        this.secureFile = secureFile
        buildHeader(truncationOffset)
    }

    @Throws(IOException::class)
    constructor(associatedFSFile: SecureFile?) : this(associatedFSFile, AccessMode.APPEND, 0)

    @Throws(IOException::class)
    override fun write(b: Int) {
        val byteToWrite = ByteArray(1)
        byteToWrite[0] = (b and 0xFF).toByte()
        write(byteToWrite, 0, 1)
    }

    @Throws(IOException::class)
    override fun write(b: ByteArray, off: Int, len: Int) {
        var off = off
        var len = len
        if (len == 0) {
            Logger.w("Nothing to write....or inconsistent args?\ngiven length : $len")
            return
        }
        try {
            var rewriteHeader = false
            while (len > 0) {
                val bytesToRead = Math.min(len, SecureIOHelper.BLOCK_PAYLOAD_SIZE - blockBufferFullness)
                System.arraycopy(b, off, blockBuffer, blockBufferFullness, bytesToRead)
                blockBufferFullness += bytesToRead
                off += bytesToRead
                len -= bytesToRead
                if (blockBufferFullness == SecureIOHelper.BLOCK_PAYLOAD_SIZE) {
                    val cipheredBuffer = SecureIOHelper.authEnc.encrypt(
                        secureFileHeader!!.associatedKeys.fileContentEncryptionKey,
                        blockBuffer,
                        SecureIOHelper.prng
                    )
                    fileAccessor.seek((lastByteWrittenPosition / SecureIOHelper.BLOCK_SIZE) * SecureIOHelper.BLOCK_SIZE)
                    fileAccessor.write(cipheredBuffer.bytes)
                    lastByteWrittenPosition =
                        (lastByteWrittenPosition / SecureIOHelper.BLOCK_SIZE) * SecureIOHelper.BLOCK_SIZE + cipheredBuffer.length
                    blockBufferFullness = 0
                    rewriteHeader = true
                }
            }
            if (rewriteHeader) {
                updateHeader()
            }
        } catch (e: InvalidKeyException) {
            Logger.e("Invalid Key : \n" + e.message, e)
        }
    }

    @Throws(IOException::class)
    private fun updateHeader() {
        val blocks = lastByteWrittenPosition / SecureIOHelper.BLOCK_SIZE - 1
        val lastBlockSize = lastByteWrittenPosition % SecureIOHelper.BLOCK_SIZE
        var plainTextSize = blocks * SecureIOHelper.BLOCK_PAYLOAD_SIZE
        if (lastBlockSize != 0L) {
            plainTextSize += SecureIOHelper.authEnc.plaintextLengthFromCiphertextLength(lastBlockSize.toInt())
        }
        secureFileHeader!!.fileSize = plainTextSize
        val header = secureFileHeader!!.buildHeaderBlock(secureFileHeader!!.associatedKeys.fileNameEncryptionKeys!!.second)
        fileAccessor.seek(0)
        fileAccessor.write(header)
    }

    @Throws(IOException::class)
    override fun close() {
        // flush kept buffer and close fileAccessor
        flush()
        fileAccessor.close()
    }

    @Throws(IOException::class)
    override fun flush() {
        try {
            if (blockBufferFullness > 0) {
                val lastBlock = Arrays.copyOfRange(blockBuffer, 0, blockBufferFullness)
                val toWrite = SecureIOHelper.authEnc.encrypt(
                    secureFileHeader!!.associatedKeys.fileContentEncryptionKey,
                    lastBlock,
                    SecureIOHelper.prng
                )
                fileAccessor.seek((lastByteWrittenPosition / SecureIOHelper.BLOCK_SIZE) * SecureIOHelper.BLOCK_SIZE)
                fileAccessor.write(toWrite.bytes)
                lastByteWrittenPosition =
                    (lastByteWrittenPosition / SecureIOHelper.BLOCK_SIZE) * SecureIOHelper.BLOCK_SIZE + toWrite.length
                updateHeader()
            }
        } catch (e: InvalidKeyException) {
            Logger.e("Invalid Key Exception : \n " + e.message, e)
            throw IOException()
        }
    }

    private fun buildHeader(truncationOffset: Long) {
        try {
            if (secureFile.fsNameFile == null) {
                throw IOException()
            }

            if (secureFile.fsNameFile!!.parent != null) {
                val dir = File(secureFile.fsNameFile!!.parent)
                if (!dir.exists()) {
                    throw FileNotFoundException("Parent directory not found")
                }
            }

            // Handle case where the file exists
            fileAccessor = RandomAccessFile(secureFile.fsNameFile, "rw")
            if (fileAccessor.length() != 0L) {
                initHeaderFromFS(truncationOffset, secureFile.fsNameFile!!.name)
            } else { // new file
                val keys = secureFile.associatedKeys!!
                val fileNameKeyPair = keys.fileNameEncryptionKeys
                // encrypt file name with authenc
                val ctrCypheredFileName = SecureIOHelper.authEnc.encrypt(
                    fileNameKeyPair!!.second,
                    secureFile.plainNameFile.name.toByteArray(StandardCharsets.UTF_8),
                    SecureIOHelper.prng
                )
                val authEncKey = KeyManagerSingleton.getInstance().generateKeyForFileEnc()
                keys.fileContentEncryptionKey = authEncKey
                // set file size to 0 and leave buffer empty
                secureFileHeader = SecureFileHeader(
                    0,
                    ctrCypheredFileName.bytes,
                    Encoded.of(authEncKey),
                    keys,
                    secureFile.plainNameFile.name.toByteArray(StandardCharsets.UTF_8)
                )
                val headerBlock = secureFileHeader!!.buildHeaderBlock(keys.fileNameEncryptionKeys!!.second)
                fileAccessor.seek(0)
                fileAccessor.write(headerBlock)
            }
        } catch (e: InvalidKeyException) {
            Logger.e("Invalid Key Exception : \n" + e.message, e)
        } catch (e: FileNotFoundException) {
            Logger.e("Invalid Key Exception : \n" + e.message, e)
        } catch (exception: IOException) {
            Logger.e("IO Exception : \n " + exception.message, exception)
        }
    }

    @Throws(IOException::class)
    private fun initHeaderFromFS(truncationOffset: Long, FSFileName: String) {
        secureFileHeader = SecureIOHelper.getSecureFileHeaderFromFS(fileAccessor, FSFileName, true)
        if (secureFileHeader == null) {
            return
        }
        when (accessMode) {
            AccessMode.APPEND -> {
                setBufferFullnessAndWritePosition(fileAccessor.length())
            }
            AccessMode.TRUNCATE -> {
                val encryptedTruncationOffset =
                    SecureIOHelper.computeEncryptedDataOffsetFromPlainDataOffset(truncationOffset)

                // future file size will have truncationOffset value as plain data length
                secureFileHeader!!.fileSize = truncationOffset
                val headerBytes =
                    secureFileHeader!!.buildHeaderBlock(secureFileHeader!!.associatedKeys.fileNameEncryptionKeys!!.second)
                fileAccessor.seek(0)
                fileAccessor.write(headerBytes)

                setBufferFullnessAndWritePosition(encryptedTruncationOffset)
                // truncate file abruptly
                fileAccessor.setLength(encryptedTruncationOffset)
                fileAccessor.seek(encryptedTruncationOffset)
            }
        }
    }

    @Throws(IOException::class)
    private fun setBufferFullnessAndWritePosition(writeOffset: Long) {
        val tmpBf = ByteArray((writeOffset % SecureIOHelper.BLOCK_SIZE).toInt())
        if (tmpBf.isNotEmpty()) {
            // last block not filled
            fileAccessor.seek(writeOffset - tmpBf.size)

            // read last bytes written in last block
            SecureIOHelper.bulletProofRead(fileAccessor, tmpBf)

            try {
                val tmpBf1 = SecureIOHelper.authEnc.decrypt(
                    secureFileHeader!!.associatedKeys.fileContentEncryptionKey,
                    EncryptedBytes(tmpBf)
                )!!
                System.arraycopy(tmpBf1, 0, blockBuffer, 0, tmpBf1.size)
                blockBufferFullness = tmpBf1.size
                lastByteWrittenPosition = writeOffset
            } catch (e: InvalidKeyException) {
                Logger.e("Invalid Key Exception : \n" + e.message, e)
                throw IOException()
            } catch (e: DecryptionException) {
                Logger.e("Decryption error : \n" + e.message, e)
                throw IOException()
            }
        }
    }
}
