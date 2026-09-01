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

import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType
import io.olvid.engine.engine.types.sync.ObvSyncSnapshot


class ObvProfileBackupsForRestore(
    status: Status?,
    snapshots: MutableList<ObvProfileBackupForRestore?>?,
    deviceList: ObvDeviceList?
) {
    @JvmField val status: Status?
    @JvmField val snapshots: MutableList<ObvProfileBackupForRestore?>? // null in case of error
    @JvmField val deviceList: ObvDeviceList? // null in case of error or if snapshots is empty

    init {
        this.status = status
        this.snapshots = snapshots
        this.deviceList = deviceList
    }

    class ObvProfileBackupForRestore {
        @JvmField var bytesBackupThreadId: ByteArray? = null
        @JvmField var version: Long = 0
        @JvmField var timestamp: Long = 0
        @JvmField var fromThisDevice: Boolean = false
        @JvmField var additionalInfo: MutableMap<String?, String?>? = null
        @JvmField var contactCount: Int = 0
        @JvmField var groupCount: Int = 0
        @JvmField var keycloakStatus: KeycloakStatus? = null
        @JvmField var keycloakServerUrl: String? = null
        @JvmField var supportedAuthenticationMethods: MutableList<ObvKeycloakAuthType?>? = null
        @JvmField var snapshot: ObvSyncSnapshot? = null
    }


    enum class Status {
        SUCCESS,
        NETWORK_ERROR,
        PERMANENT_ERROR,  // unknown key, or invalid snapshot
        ERROR,
        TRUNCATED,
    }

    enum class KeycloakStatus {
        UNMANAGED,
        MANAGED,
        TRANSFER_RESTRICTED,
    }
}
