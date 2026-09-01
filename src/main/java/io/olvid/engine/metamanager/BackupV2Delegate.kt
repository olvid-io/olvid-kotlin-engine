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
package io.olvid.engine.metamanager

import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.engine.types.ObvDeviceBackupForRestore
import io.olvid.engine.engine.types.ObvProfileBackupsForRestore

interface BackupV2Delegate {
    @Throws(Exception::class)
    fun generateDeviceBackupSeed(server: String?): String? // throws an exception if an active device backup seed already exists

    @get:Throws(Exception::class)
    val currentDeviceBackupSeed: String?

    @Throws(Exception::class)
    fun deleteDeviceBackupSeed(backupSeed: BackupSeed?)
    fun backupDeviceAndProfilesNow(): Boolean
    fun fetchDeviceBackup(server: String?, backupSeed: BackupSeed?): ObvDeviceBackupForRestore?
    fun fetchProfileBackups(server: String?, backupSeed: BackupSeed?): ObvProfileBackupsForRestore?
    fun deleteProfileBackupSnapshot(
        server: String?,
        backupSeed: BackupSeed?,
        backupThreadId: UID?,
        version: Long
    ): Boolean
}
