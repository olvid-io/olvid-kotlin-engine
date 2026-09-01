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

import io.olvid.engine.Logger
import io.olvid.engine.backup.datatypes.BackupManagerSessionFactory
import io.olvid.engine.backup.datatypes.BackupTaskStatus
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.containers.BackupsV2ListItem
import io.olvid.engine.datatypes.containers.BackupsV2ListItem.Companion.manyOf
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2ListBackupsQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvDeviceBackupForRestore
import io.olvid.engine.engine.types.sync.ObvDeviceBackupSnapshot
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import javax.net.ssl.SSLSocketFactory


class DeviceBackupFetchTask(
    private val server: String?,
    private val deviceBackupSeed: BackupSeed,
    private val backupManagerSessionFactory: BackupManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?
) {
    var obvDeviceBackupForRestore: ObvDeviceBackupForRestore? = null
        private set

    fun execute(): BackupTaskStatus {
        val derivedKeysV2 = deviceBackupSeed.deriveKeysV2()

        /**//// */
        // 1. list device backups
        val standaloneServerQueryOperation = StandaloneServerQueryOperation(
            ServerQuery(
                null,
                null,
                BackupsV2ListBackupsQuery(server, derivedKeysV2.backupKeyUid)
            ), sslSocketFactory, userAgentOverride
        )
        val queue = OperationQueue()
        queue.queue(standaloneServerQueryOperation)
        queue.execute(1, "Engine-DeviceBackupFetchTask")
        queue.join()

        var deviceBackupDownloadUrl: String? = null

        if (standaloneServerQueryOperation.isFinished) {
            val backupsV2ListItems: MutableList<BackupsV2ListItem>?
            try {
                backupsV2ListItems =
                    manyOf(standaloneServerQueryOperation.serverResponse!!.decodeList())
            } catch (e: Exception) {
                Logger.x(e)
                return BackupTaskStatus.RETRIABLE_FAILURE
            }

            for (backupsV2ListItem in backupsV2ListItems) {
                if (backupsV2ListItem.threadId == Constants.DEVICE_BACKUP_THREAD_ID) {
                    deviceBackupDownloadUrl = backupsV2ListItem.downloadUrl
                    break
                }
            }
        } else {
            val rfc = standaloneServerQueryOperation.reasonForCancel
            if (rfc == null) {
                return BackupTaskStatus.RETRIABLE_FAILURE
            } else if (rfc == StandaloneServerQueryOperation.RFC_NETWORK_ERROR) {
                obvDeviceBackupForRestore = ObvDeviceBackupForRestore(
                    ObvDeviceBackupForRestore.Status.NETWORK_ERROR,
                    null,
                    null
                )
                return BackupTaskStatus.RETRIABLE_FAILURE
            } else if (rfc != StandaloneServerQueryOperation.RFC_UNKNOWN_BACKUP_UID) {
                // can be: general error, server parsing error
                return BackupTaskStatus.RETRIABLE_FAILURE
            }
        }

        /**//// */
        // 2. fail if no device backup was found
        if (deviceBackupDownloadUrl == null) {
            return BackupTaskStatus.PERMANENT_FAILURE
        }

        /**/// */
        // 3. download the backup file
        val serverMethod = DownloadBackupFromServer(deviceBackupDownloadUrl)
        if (!serverMethod.execute()) {
            obvDeviceBackupForRestore = ObvDeviceBackupForRestore(
                ObvDeviceBackupForRestore.Status.NETWORK_ERROR,
                null,
                null
            )
            return BackupTaskStatus.RETRIABLE_FAILURE
        }

        try {
            backupManagerSessionFactory.session.use { backupManagerSession ->  /**///// */
                // 4. decrypt the encrypted device backup
                val obvDeviceBackupSnapshot: ObvDeviceBackupSnapshot?
                try {
                    val encryptedBackup = EncryptedBytes(serverMethod.encryptedBackup!!)

                    // decrypt
                    val authEnc = Suite.getAuthEnc(derivedKeysV2.encryptionKey)!!
                    val paddedPlaintext =
                        authEnc.decrypt(derivedKeysV2.encryptionKey, encryptedBackup)!!

                    // decode
                    val encodedDictionary: HashMap<DictionaryKey, Encoded> =
                        Encoded(paddedPlaintext).decodeDictionaryWithPadding()

                    obvDeviceBackupSnapshot = ObvDeviceBackupSnapshot.fromEncodedDictionary(
                        encodedDictionary,
                        backupManagerSession.identityDelegate!!.syncDelegate!!,
                        backupManagerSession.appBackupAndSyncDelegate!!
                    )
                } catch (e: Exception) {
                    // if the backup cannot be decrypted or decoded, no need to retry
                    Logger.x(e)
                    return BackupTaskStatus.PERMANENT_FAILURE
                }
                if (obvDeviceBackupSnapshot == null) {
                    return BackupTaskStatus.PERMANENT_FAILURE
                }


                /**/////// */
                // 5. convert the ObvDeviceBackupSnapshot to an ObvDeviceBackupForRestore
                val profiles =
                    backupManagerSession.identityDelegate.getDeviceBackupProfileListFromDeviceBackup(
                        backupManagerSession.session,
                        obvDeviceBackupSnapshot.getSnapshotNode(backupManagerSession.identityDelegate.syncDelegate!!.tag)
                    )
                obvDeviceBackupForRestore = ObvDeviceBackupForRestore(
                    ObvDeviceBackupForRestore.Status.SUCCESS,
                    profiles,
                    obvDeviceBackupSnapshot.getSnapshotNode(backupManagerSession.appBackupAndSyncDelegate.tag)
                )
            }
        } catch (e: Exception) {
            Logger.x(e)
            return BackupTaskStatus.PERMANENT_FAILURE
        }
        return BackupTaskStatus.SUCCESS
    }
}
