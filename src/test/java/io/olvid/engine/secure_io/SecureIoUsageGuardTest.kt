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

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Completeness guard for the EngineFileIo abstraction.
 *
 * The single-engine design (Android plain files, desktop/daemon encrypted at rest) relies on every
 * engine file-content read/write going through the injected [io.olvid.engine.storage.EngineFileIo]
 * strategy. The concrete file-I/O implementations must live in exactly two places:
 *  - the `storage` package: [io.olvid.engine.storage.PlainFileIo] (raw java.io, the Android default);
 *  - the `secure_io` package: SecureFileIo / SecureFile* (encrypted at rest, the desktop provider).
 *
 * Anywhere else in engine production code, constructing a raw java.io byte stream
 * (FileInputStream / FileOutputStream / RandomAccessFile) or a SecureFile* directly bypasses the
 * strategy — on Android a SecureFile would NPE (KeyManagerSingleton is never initialized), and a raw
 * stream on the desktop would be a plaintext leak. So instead of a manual checklist we enforce the
 * invariant by walking the sources. This catches a missed conversion today and any reintroduced one
 * in future develop syncs.
 */
class SecureIoUsageGuardTest {

    @Test
    fun all_engine_file_io_goes_through_the_strategy() {
        val root = engineMainSourceRoot()
        val forbidden = Regex(
            """\b(FileInputStream|FileOutputStream|RandomAccessFile|SecureFileInputStream|SecureFileOutputStream|SecureFile)\s*\("""
        )
        val violations = mutableListOf<String>()

        root.walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
            .filter {
                val unixPath = it.path.replace(File.separatorChar, '/')
                "/secure_io/" !in unixPath && "/storage/" !in unixPath
            }
            .forEach { file ->
                file.readLines().forEachIndexed { index, line ->
                    val trimmed = line.trimStart()
                    if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
                        return@forEachIndexed
                    }
                    if (forbidden.containsMatchIn(line)) {
                        violations.add("${file.name}:${index + 1}: ${line.trim()}")
                    }
                }
            }

        assertTrue(
            "Engine file content must be read/written through the EngineFileIo strategy obtained from " +
                "the *ManagerSession, not by constructing raw java.io byte streams or SecureFile* " +
                "directly. The concrete implementations belong in the storage/ and secure_io/ " +
                "packages only. Offending sites:\n" + violations.joinToString("\n"),
            violations.isEmpty()
        )
    }

    private fun engineMainSourceRoot(): File {
        val candidates = listOf(
            "src/main/java/io/olvid/engine",
            "obv_engine/engine/src/main/java/io/olvid/engine",
            "engine/src/main/java/io/olvid/engine",
        )
        var dir: File? = File(System.getProperty("user.dir"))
        repeat(8) {
            val current = dir ?: return@repeat
            for (candidate in candidates) {
                val resolved = File(current, candidate)
                if (resolved.isDirectory) {
                    return resolved
                }
            }
            dir = current.parentFile
        }
        throw IllegalStateException(
            "Could not locate the engine main source root from working dir " +
                System.getProperty("user.dir")
        )
    }
}
