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
import io.olvid.engine.backup.databases.DeviceBackupSeed
import io.olvid.engine.backup.databases.ProfileBackupThreadId
import io.olvid.engine.backup.datatypes.BackupManagerSessionFactory
import io.olvid.engine.backup.datatypes.BackupTaskStatus
import io.olvid.engine.crypto.Signature
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.containers.BackupsV2ListItem
import io.olvid.engine.datatypes.containers.BackupsV2ListItem.Companion.manyOf
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2DeleteBackupQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2ListBackupsQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import javax.net.ssl.SSLSocketFactory


class DeviceBackupDeleteTask(
    private val backupManagerSessionFactory: BackupManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val deviceBackupSeed: BackupSeed
) {
    fun execute(): BackupTaskStatus {
        try {
            backupManagerSessionFactory.session.use { backupManagerSession ->
                val deviceBackupSeed: DeviceBackupSeed =
                    DeviceBackupSeed.get(backupManagerSession, this.deviceBackupSeed) ?: // seed was already deleted, everything is fine
                    return BackupTaskStatus.PERMANENT_FAILURE

                val deviceServer = deviceBackupSeed.server
                val deviceDerivedKeysV2 = deviceBackupSeed.backupSeed.deriveKeysV2()

                /**//// */
                // 1. list device backups
                var standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        null,
                        BackupsV2ListBackupsQuery(deviceServer, deviceDerivedKeysV2.backupKeyUid)
                    ), sslSocketFactory, userAgentOverride
                )
                var queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-DeviceBackupDeleteTask")
                queue.join()

                var deviceVersion: Long? = null

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
                            deviceVersion = backupsV2ListItem.version
                            break
                        }
                    }
                } else {
                    val rfc = standaloneServerQueryOperation.reasonForCancel
                    if (rfc == null || rfc != StandaloneServerQueryOperation.RFC_UNKNOWN_BACKUP_UID) {
                        // can be: general error, server parsing error
                        return BackupTaskStatus.RETRIABLE_FAILURE
                    }
                }

                /**/// */
                // 2. delete the device backup if one was found
                if (deviceVersion != null) {
                    // compute the signature
                    val signaturePayload = Encoded.of(
                        arrayOf(
                            Encoded.of(deviceDerivedKeysV2.backupKeyUid),
                            Encoded.of(Constants.DEVICE_BACKUP_THREAD_ID),
                            Encoded.of(deviceVersion),
                        )
                    ).bytes
                    val signature = Signature.sign(
                        Constants.SignatureContext.BACKUP_DELETE,
                        signaturePayload,
                        deviceDerivedKeysV2.authenticationKeyPair.getPrivateKey().signaturePrivateKey,
                        backupManagerSession.prng!!
                    )

                    standaloneServerQueryOperation = StandaloneServerQueryOperation(
                        ServerQuery(
                            null,
                            null,
                            BackupsV2DeleteBackupQuery(
                                deviceServer,
                                deviceDerivedKeysV2.backupKeyUid,
                                Constants.DEVICE_BACKUP_THREAD_ID,
                                deviceVersion,
                                signature
                            )
                        ), sslSocketFactory, userAgentOverride
                    )
                    queue = OperationQueue()
                    queue.queue(standaloneServerQueryOperation)
                    queue.execute(1, "Engine-DeviceBackupDeleteTask")
                    queue.join()

                    if (!standaloneServerQueryOperation.isFinished) {
                        // can be: general error, server parsing error, unknown backup uid, unknown threadId, unknown version, invalid signature
                        return BackupTaskStatus.RETRIABLE_FAILURE
                    }
                }


                /**///// */
                // 3. delete all profile backups (if there is no active backup key)
                if (DeviceBackupSeed.getActive(backupManagerSession) == null) {
                    for (profileBackupThreadId in ProfileBackupThreadId.getAll(
                        backupManagerSession
                    )) {
                        val server: String = profileBackupThreadId.ownedIdentity.server
                        val backupSeed =
                            backupManagerSession.identityDelegate!!.getOwnedIdentityBackupSeed(
                                backupManagerSession.session,
                                profileBackupThreadId.ownedIdentity
                            )
                        if (backupSeed == null) {
                            // profile has no backup seed, nothing to delete
                            continue
                        }
                        val derivedKeysV2 = backupSeed.deriveKeysV2()


                        /**///// */
                        // 3.1. list profile backups
                        standaloneServerQueryOperation = StandaloneServerQueryOperation(
                            ServerQuery(
                                null,
                                null,
                                BackupsV2ListBackupsQuery(server, derivedKeysV2.backupKeyUid)
                            ), sslSocketFactory, userAgentOverride
                        )
                        queue = OperationQueue()
                        queue.queue(standaloneServerQueryOperation)
                        queue.execute(1, "Engine-DeviceBackupDeleteTask")
                        queue.join()

                        var version: Long? = null

                        if (standaloneServerQueryOperation.isFinished) {
                            val backupsV2ListItems: MutableList<BackupsV2ListItem>?
                            try {
                                backupsV2ListItems = manyOf(
                                    standaloneServerQueryOperation.serverResponse!!.decodeList()
                                )
                            } catch (e: Exception) {
                                Logger.x(e)
                                return BackupTaskStatus.RETRIABLE_FAILURE
                            }

                            for (backupsV2ListItem in backupsV2ListItems) {
                                if (backupsV2ListItem.threadId == profileBackupThreadId.threadId) {
                                    version = backupsV2ListItem.version
                                    break
                                }
                            }
                        } else {
                            val rfc = standaloneServerQueryOperation.reasonForCancel
                            if (rfc == null || rfc != StandaloneServerQueryOperation.RFC_UNKNOWN_BACKUP_UID) {
                                // can be: general error, server parsing error
                                return BackupTaskStatus.RETRIABLE_FAILURE
                            }
                        }

                        /**/// */
                        // 3.2. delete the profile backup if one was found
                        if (version != null) {
                            val signaturePayload = Encoded.of(
                                arrayOf(
                                    Encoded.of(derivedKeysV2.backupKeyUid),
                                    Encoded.of(profileBackupThreadId.threadId),
                                    Encoded.of(version),
                                )
                            ).bytes
                            val signature = Signature.sign(
                                Constants.SignatureContext.BACKUP_DELETE,
                                signaturePayload,
                                derivedKeysV2.authenticationKeyPair.getPrivateKey().signaturePrivateKey,
                                backupManagerSession.prng!!
                            )

                            standaloneServerQueryOperation = StandaloneServerQueryOperation(
                                ServerQuery(
                                    null,
                                    null,
                                    BackupsV2DeleteBackupQuery(
                                        server,
                                        derivedKeysV2.backupKeyUid,
                                        profileBackupThreadId.threadId,
                                        version,
                                        signature
                                    )
                                ), sslSocketFactory, userAgentOverride
                            )
                            queue = OperationQueue()
                            queue.queue(standaloneServerQueryOperation)
                            queue.execute(1, "Engine-DeviceBackupDeleteTask")
                            queue.join()

                            if (!standaloneServerQueryOperation.isFinished) {
                                // can be: general error, server parsing error, unknown backup uid, unknown threadId, unknown version, invalid signature
                                return BackupTaskStatus.RETRIABLE_FAILURE
                            }
                        }
                    }
                }
                return BackupTaskStatus.SUCCESS
            }
        } catch (e: Exception) {
            Logger.x(e)
            return BackupTaskStatus.RETRIABLE_FAILURE
        }
    }
}
