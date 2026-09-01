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
import io.olvid.engine.secure_io.datatypes.DirectoryListingResult
import io.olvid.engine.secure_io.datatypes.FileKeys
import io.olvid.engine.storage.EngineFile
import io.olvid.engine.storage.EngineInputStream
import io.olvid.engine.storage.EngineWriteMode
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException

class SecureFile private constructor(plainFile: File?) : EngineFile {

    internal val associatedKeys: FileKeys?
    override val plainNameFile: File
    internal var fsNameFile: File?
        private set
    internal val isDirectory: Boolean

    init {
        if (plainFile != null) {
            isDirectory = plainFile.isDirectory
            associatedKeys =
                if (isDirectory) null else FileKeys(KeyManagerSingleton.getInstance().generateKeysForFileName())
            fsNameFile = if (isDirectory) {
                plainFile
            } else {
                SecureIOHelper.buildFileFromPlainFileName(plainFile.parent, plainFile.name, associatedKeys!!)
            }
            plainNameFile = plainFile
        } else {
            throw NullPointerException()
        }
    }

    constructor(absolutePath: String) : this(File(absolutePath))

    constructor(givenBaseDir: String?, fileName: String) : this(File(givenBaseDir, fileName))

    // Public

    @Throws(IOException::class)
    fun renameTo(newDir: String?, newName: String?): Boolean {
        try {
            if (newDir != null && newName != null) {
                val keys = associatedKeys!!
                val targetFile = SecureIOHelper.buildFileFromPlainFileName(newDir, newName, keys)

                if (fsNameFile == null || targetFile == null) {
                    Logger.e("Couldn't build FS file names")
                    return false
                }

                if (fsNameFile!!.renameTo(targetFile)) {
                    Logger.d("Renamed file to $newDir/$newName successfully....updating header ")
                    val fileAccessor = RandomAccessFile(targetFile, "rw")
                    // get header from FS
                    val fileHeader = SecureIOHelper.getSecureFileHeaderFromFS(fileAccessor, targetFile.name, false)
                    if (fileHeader != null) {
                        // set new encrypted file name in header object
                        fileHeader.encryptedFileName = SecureIOHelper.authEnc.encrypt(
                            keys.fileNameEncryptionKeys!!.second,
                            newName.toByteArray(StandardCharsets.UTF_8),
                            SecureIOHelper.prng
                        ).bytes
                        // rebuild header with updated values
                        val newHeader = fileHeader.buildHeaderBlock(keys.fileNameEncryptionKeys!!.second)
                        fileAccessor.seek(0)
                        fileAccessor.write(newHeader)
                        fileAccessor.close()
                        fsNameFile = File(targetFile.parent, newName)
                        Logger.d("Updated header successfully")
                        return true
                    }
                } else {
                    Logger.d("Couldn't update header on FS")
                    throw IOException()
                }
            }
            throw IllegalArgumentException()
        } catch (invalidKeyException: InvalidKeyException) {
            Logger.e("Bad key used for HMAC SHA256 generation", invalidKeyException)
            throw IOException()
        }
    }

    @Throws(IOException::class)
    override fun listDirectory(): DirectoryListingResult? {
        if (!plainNameFile.isDirectory) {
            Logger.e("File is not a directory, can't list...")
            throw IOException()
        }

        val directoryListingResult = DirectoryListingResult()
        val childrenNames = plainNameFile.list()
        if (childrenNames != null) {
            for (child in childrenNames) {
                val childFile = File(plainNameFile.absolutePath + File.separator + child)
                if (childFile.isDirectory) {
                    directoryListingResult.dirList.add(childFile)
                    continue
                }
                val randomAccessFile = RandomAccessFile(childFile, "r")
                // try to read header
                val secureFileHeader = SecureIOHelper.getSecureFileHeaderFromFS(randomAccessFile, child, true)
                if (secureFileHeader != null) {
                    val secureFile = SecureFile(
                        plainNameFile.absolutePath + File.separator + String(secureFileHeader.plainFileName)
                    )
                    directoryListingResult.managedFileList.add(secureFile)
                } else { // normal file or directory
                    directoryListingResult.fileList.add(childFile)
                }
            }
            return directoryListingResult
        }
        return null
    }

    @Throws(IOException::class)
    override fun delete(): Boolean {
        return fsNameFile?.delete() ?: false
    }

    override fun exists(): Boolean {
        return fsNameFile != null && fsNameFile!!.exists()
    }

    override fun canRead(): Boolean {
        var secureFileHeader: SecureFileHeader?
        try {
            val randomAccessFile = RandomAccessFile(fsNameFile, "r")
            // try to read header
            secureFileHeader = SecureIOHelper.getSecureFileHeaderFromFS(randomAccessFile, fsNameFile!!.name, true)
        } catch (_: IOException) {
            Logger.d("couldn't read header of file : " + plainNameFile.name)
            secureFileHeader = null
        }
        return secureFileHeader != null
    }

    override fun length(): Long {
        return fsNameFile?.length() ?: 0L
    }

    override fun isFile(): Boolean {
        return fsNameFile!!.isFile
    }

    @Throws(IOException::class)
    override fun openInput(): EngineInputStream {
        return SecureFileInputStream(this)
    }

    @Throws(IOException::class)
    override fun openOutput(): OutputStream {
        return SecureFileOutputStream(this)
    }

    @Throws(IOException::class)
    override fun openOutput(mode: EngineWriteMode, truncationOffset: Long): OutputStream {
        val accessMode = when (mode) {
            EngineWriteMode.TRUNCATE -> SecureFileOutputStream.AccessMode.TRUNCATE
            EngineWriteMode.APPEND -> SecureFileOutputStream.AccessMode.APPEND
        }
        return SecureFileOutputStream(this, accessMode, truncationOffset)
    }
}
