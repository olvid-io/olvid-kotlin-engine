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

import io.olvid.engine.storage.EngineFile
import io.olvid.engine.storage.EngineFileIo

/**
 * Encrypted-at-rest [EngineFileIo] — the desktop/daemon implementation. Wraps the existing [SecureFile]
 * verbatim (hashed file names, per-file keys, headers, encrypted seeds). Requires an initialized
 * [KeyManagerSingleton] (the desktop password flow calls `tryToInitKeyManagement` before engine
 * construction), so it must never be selected on Android.
 */
class SecureFileIo : EngineFileIo {
    override fun file(absolutePath: String): EngineFile = SecureFile(absolutePath)
    override fun file(baseDir: String?, name: String): EngineFile = SecureFile(baseDir, name)
}
