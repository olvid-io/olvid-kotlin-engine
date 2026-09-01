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

import io.olvid.engine.datatypes.UID
import io.olvid.engine.engine.types.ObvBackupKeyInformation
import io.olvid.engine.engine.types.identities.ObvIdentity

interface BackupDelegate {
    //    void generateNewBackupKey();
    //    int verifyBackupKey(String seedString);
    fun stopLegacyBackups()
    fun setAutoBackupEnabled(enabled: Boolean, initiateBackupNowIfNeeded: Boolean)
    fun initiateBackup(forExpert: Boolean)

    fun backupFailed(tag: String?, backupKeyUid: UID, version: Int)
    fun backupSuccess(tag: String?, backupKeyUid: UID, version: Int, backupContent: String?)

    @get:Throws(Exception::class)
    val backupKeyInformation: ObvBackupKeyInformation?
    fun markBackupExported(backupKeyUid: UID, version: Int)
    fun markBackupUploaded(backupKeyUid: UID, version: Int)
    fun discardBackup(backupKeyUid: UID, version: Int)
    fun validateBackupSeed(seedString: String?, backupContent: ByteArray?): Int
    fun restoreOwnedIdentitiesFromBackup(
        seedString: String?,
        backupContent: ByteArray?,
        deviceDisplayName: String?
    ): Array<ObvIdentity?>?

    fun restoreContactsAndGroupsFromBackup(
        seedString: String?,
        backupContent: ByteArray?,
        restoredOwnedIdentities: Array<ObvIdentity?>?
    )
}
