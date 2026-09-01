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

package io.olvid.engine.secure_io.datatypes

import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACKey

class FileKeys {
    var fileNameEncryptionKeys: Pair<MACKey, AuthEncKey>?
    var fileContentEncryptionKey: AuthEncKey?

    constructor(
        fileNameEncryptionKeys: Pair<MACKey, AuthEncKey>?,
        fileContentEncryptionKey: AuthEncKey?
    ) {
        require(!(fileContentEncryptionKey == null || fileNameEncryptionKeys == null))
        this.fileNameEncryptionKeys = fileNameEncryptionKeys
        this.fileContentEncryptionKey = fileContentEncryptionKey
    }

    constructor(fileNameEncryptionKeys: Pair<MACKey, AuthEncKey>?) {
        this.fileNameEncryptionKeys = fileNameEncryptionKeys
        this.fileContentEncryptionKey = null
    }
}
