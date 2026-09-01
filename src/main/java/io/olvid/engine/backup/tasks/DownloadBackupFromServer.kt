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
package io.olvid.engine.backup.tasks

import io.olvid.engine.datatypes.ServerMethodForS3


internal class DownloadBackupFromServer(private val backupDownloadUrl: String?) :
    ServerMethodForS3() {
    var encryptedBackup: ByteArray? = null
        private set


    override fun getUrl(): String? {
        return backupDownloadUrl
    }

    override fun getDataToSend(): ByteArray {
        return ByteArray(0)
    }

    override fun handleReceivedData(receivedData: ByteArray?) {
        this.encryptedBackup = receivedData
    }

    override fun getMethod(): String {
        return METHOD_GET
    }

    override fun isActiveIdentityRequired(): Boolean {
        return false
    }

    fun execute(): Boolean {
        return super.execute(false) == OK
    }
}
