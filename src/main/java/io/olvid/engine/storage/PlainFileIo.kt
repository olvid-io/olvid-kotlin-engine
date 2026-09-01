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
package io.olvid.engine.storage

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile

/**
 * Plain (un-encrypted) [EngineFileIo] — the Android default. Reproduces the engine's historical raw
 * `java.io` file behavior verbatim. This is the ONLY place outside the `secure_io` provider allowed to
 * construct raw `java.io` streams (enforced by SecureIoUsageGuardTest).
 */
class PlainFileIo : EngineFileIo {
    override fun file(absolutePath: String): EngineFile = PlainFile(File(absolutePath))
    override fun file(baseDir: String?, name: String): EngineFile = PlainFile(File(baseDir, name))
}

private class PlainFile(override val plainNameFile: File) : EngineFile {
    override fun exists(): Boolean = plainNameFile.exists()

    @Throws(IOException::class)
    override fun delete(): Boolean = plainNameFile.delete()

    override fun length(): Long = plainNameFile.length()

    override fun isFile(): Boolean = plainNameFile.isFile

    override fun canRead(): Boolean = plainNameFile.canRead()

    @Throws(IOException::class)
    override fun listDirectory(): EngineDirectoryListing? {
        if (!plainNameFile.isDirectory) {
            throw IOException("File is not a directory, can't list...")
        }
        val children = plainNameFile.list() ?: return null
        val listing = MutableEngineDirectoryListing()
        for (child in children) {
            val childFile = File(plainNameFile, child)
            if (childFile.isDirectory) {
                listing.dirList.add(childFile)
            } else {
                // in plain mode every regular file is an engine-managed file (no header to parse)
                listing.managedFileList.add(PlainFile(childFile))
            }
        }
        return listing
    }

    @Throws(IOException::class)
    override fun openInput(): EngineInputStream = PlainEngineInputStream(plainNameFile)

    @Throws(IOException::class)
    override fun openOutput(): OutputStream = FileOutputStream(plainNameFile)

    @Throws(IOException::class)
    override fun openOutput(mode: EngineWriteMode, truncationOffset: Long): OutputStream =
        when (mode) {
            EngineWriteMode.APPEND -> FileOutputStream(plainNameFile, true)
            EngineWriteMode.TRUNCATE -> TruncatingFileOutputStream(plainNameFile, truncationOffset)
        }
}

/**
 * Sequential output stream backed by a [RandomAccessFile] that first sets the file length to
 * [truncationOffset] and positions the write cursor there — reproduces the engine's
 * `setLength(offset); seek(offset); write(...)` chunked-write pattern.
 */
private class TruncatingFileOutputStream
@Throws(IOException::class) constructor(file: File, truncationOffset: Long) : OutputStream() {
    private val randomAccessFile = RandomAccessFile(file, "rw")

    init {
        randomAccessFile.setLength(truncationOffset)
        randomAccessFile.seek(truncationOffset)
    }

    @Throws(IOException::class)
    override fun write(b: Int) = randomAccessFile.write(b)

    @Throws(IOException::class)
    override fun write(b: ByteArray, off: Int, len: Int) = randomAccessFile.write(b, off, len)

    @Throws(IOException::class)
    override fun close() = randomAccessFile.close()
}

/** Random-access input stream backed by a read-only [RandomAccessFile]. */
private class PlainEngineInputStream
@Throws(IOException::class) constructor(file: File) : EngineInputStream() {
    private val randomAccessFile = RandomAccessFile(file, "r")

    @Throws(IOException::class)
    override fun read(): Int = randomAccessFile.read()

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int = randomAccessFile.read(b, off, len)

    @Throws(IOException::class)
    override fun seek(index: Long) = randomAccessFile.seek(index)

    @Throws(IOException::class)
    override fun close() = randomAccessFile.close()
}

internal class MutableEngineDirectoryListing : EngineDirectoryListing {
    override val managedFileList: MutableList<EngineFile> = ArrayList()
    override val fileList: MutableList<File> = ArrayList()
    override val dirList: MutableList<File> = ArrayList()
}
