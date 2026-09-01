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
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Strategy for all engine file-content I/O (identity photos, attachments, downloaded user data).
 *
 * Two implementations exist:
 *  - [PlainFileIo] (Android default): plain java.io files, no encryption.
 *  - SecureFileIo (desktop): the secure_io encrypted-at-rest implementation.
 *
 * The implementation is injected at Engine construction and threaded onto every *ManagerSession, so
 * call-sites obtain it from their session and never name a concrete file-I/O class. Enforced by
 * SecureIoUsageGuardTest.
 */
interface EngineFileIo {
    fun file(absolutePath: String): EngineFile
    fun file(baseDir: String?, name: String): EngineFile
}

/** Write positioning mode for [EngineFile.openOutput]. */
enum class EngineWriteMode { TRUNCATE, APPEND }

/** An input stream that additionally supports random access via [seek] (used for chunked uploads). */
abstract class EngineInputStream : InputStream() {
    @Throws(IOException::class)
    abstract fun seek(index: Long)
}

/**
 * Handle to an engine file. [plainNameFile] is the logical (plaintext-named) File used for path/name
 * operations; the concrete on-disk representation (plain vs encrypted, hashed name) is hidden.
 */
interface EngineFile {
    val plainNameFile: File

    fun exists(): Boolean

    @Throws(IOException::class)
    fun delete(): Boolean

    fun length(): Long

    fun isFile(): Boolean

    fun canRead(): Boolean

    @Throws(IOException::class)
    fun listDirectory(): EngineDirectoryListing?

    @Throws(IOException::class)
    fun openInput(): EngineInputStream

    @Throws(IOException::class)
    fun openOutput(): OutputStream

    @Throws(IOException::class)
    fun openOutput(mode: EngineWriteMode, truncationOffset: Long): OutputStream
}

/**
 * Result of [EngineFile.listDirectory].
 * - [managedFileList]: engine-managed files (the encrypted/decryptable files in SecureIO; all regular
 *   files in plain mode). Their [EngineFile.plainNameFile] gives the logical name.
 * - [fileList]: non-managed plain files encountered (e.g. files being written, or non-secure files in
 *   SecureIO; always empty in plain mode).
 * - [dirList]: sub-directories.
 */
interface EngineDirectoryListing {
    val managedFileList: MutableList<EngineFile>
    val fileList: MutableList<File>
    val dirList: MutableList<File>
}
