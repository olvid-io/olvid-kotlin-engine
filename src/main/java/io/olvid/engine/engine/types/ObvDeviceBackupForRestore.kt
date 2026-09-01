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
package io.olvid.engine.engine.types

import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode


class ObvDeviceBackupForRestore(
    status: Status?,
    profiles: MutableList<ObvDeviceBackupProfile?>?,
    appDeviceBackupSnapshot: ObvSyncSnapshotNode?
) {
    @JvmField val status: Status?
    @JvmField val profiles: MutableList<ObvDeviceBackupProfile?>? // null in case of error
    @JvmField val appDeviceBackupSnapshot: ObvSyncSnapshotNode? // null in case of error

    init {
        this.status = status
        this.profiles = profiles
        this.appDeviceBackupSnapshot = appDeviceBackupSnapshot
    }

    class ObvDeviceBackupProfile {
        @JvmField var bytesProfileIdentity: ByteArray? = null
        @JvmField var identityDetails: JsonIdentityDetailsWithVersionAndPhoto? = null
        @JvmField var keycloakManaged: Boolean = false
        @JvmField var profileBackupSeed: String? = null
    }


    enum class Status {
        SUCCESS,
        NETWORK_ERROR,
        PERMANENT_ERROR,  // unknown key, or invalid snapshot
        ERROR,
    }
}
