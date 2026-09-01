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
import io.olvid.engine.backup.datatypes.BackupManagerSessionFactory
import io.olvid.engine.backup.datatypes.BackupTaskStatus
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.containers.BackupsV2ListItem
import io.olvid.engine.datatypes.containers.BackupsV2ListItem.Companion.manyOf
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2CreateBackupQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2ListBackupsQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2UploadBackupQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvDeviceBackupSnapshot
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import java.security.InvalidKeyException
import javax.net.ssl.SSLSocketFactory


class DeviceBackupUploadTask(
    private val backupManagerSessionFactory: BackupManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?
) {
    fun execute(): BackupTaskStatus {
        try {
            backupManagerSessionFactory.session.use { backupManagerSession ->
                val deviceBackupSeed: DeviceBackupSeed =
                    DeviceBackupSeed.getActive(backupManagerSession) ?: return BackupTaskStatus.PERMANENT_FAILURE

                /**///// */
                // 0. Check we have at least one owned identity
                if (backupManagerSession.identityDelegate?.getOwnedIdentities(backupManagerSession.session)?.isEmpty() == true) {
                    return BackupTaskStatus.SUCCESS
                }


                val server = deviceBackupSeed.server
                val derivedKeysV2 = deviceBackupSeed.backupSeed.deriveKeysV2()


                /**///// */
                // 1. list existing backups
                var standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        null,
                        BackupsV2ListBackupsQuery(server, derivedKeysV2.backupKeyUid)
                    ), sslSocketFactory, userAgentOverride
                )
                var queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-DeviceBackupUploadTask")
                queue.join()

                var version: Long? = null

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
                            version = backupsV2ListItem.version
                            break
                        }
                    }
                    if (version == null) {
                        // the backup slot exists, but nothing was ever uploaded
                        version = System.currentTimeMillis()
                    }
                } else {
                    val rfc = standaloneServerQueryOperation.reasonForCancel
                    if (rfc == null || rfc != StandaloneServerQueryOperation.RFC_UNKNOWN_BACKUP_UID) {
                        // can be: general error, server parsing error
                        return BackupTaskStatus.RETRIABLE_FAILURE
                    }
                }

                /**///// */
                // 2. if backup UID does not exist yet, create one
                if (version == null) {
                    standaloneServerQueryOperation = StandaloneServerQueryOperation(
                        ServerQuery(
                            null,
                            null,
                            BackupsV2CreateBackupQuery(
                                server,
                                derivedKeysV2.backupKeyUid,
                                derivedKeysV2.authenticationKeyPair.getPublicKey()
                            )
                        ), sslSocketFactory, userAgentOverride
                    )
                    queue = OperationQueue()
                    queue.queue(standaloneServerQueryOperation)
                    queue.execute(1, "Engine-DeviceBackupUploadTask")
                    queue.join()

                    if (standaloneServerQueryOperation.isFinished) {
                        // success!
                        version = System.currentTimeMillis()
                    } else {
                        // can be: general error, server parsing error, or backup uid already exists
                        return BackupTaskStatus.RETRIABLE_FAILURE
                    }
                }

                /**////// */
                // 3. increment version number and upload a new device backup
                version++

                // 3.1 create the snapshot
                var deviceBackupSnapshot: ObvDeviceBackupSnapshot?
                try {
                    backupManagerSession.session.startTransaction()
                    val identityBackupAndSyncDelegate =
                        backupManagerSession.identityDelegate!!.getSyncDelegateWithinTransaction(
                            backupManagerSession.session
                        )
                    deviceBackupSnapshot = ObvDeviceBackupSnapshot.get(
                        identityBackupAndSyncDelegate,
                        backupManagerSession.appBackupAndSyncDelegate!!
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                    return BackupTaskStatus.RETRIABLE_FAILURE
                } finally {
                    backupManagerSession.session.rollback()
                }

                // 3.2 encode and encrypt and compute signature
                val encryptedBackup: EncryptedBytes
                val signature: ByteArray?
                run {
                    // encode
                    val plaintextContent = Encoded.of(
                        deviceBackupSnapshot.toEncodedDictionary(
                            backupManagerSession.identityDelegate.syncDelegate!!,
                            backupManagerSession.appBackupAndSyncDelegate
                        )!!
                    )

                    // add a padding to obfuscate content length
                    val paddedPlaintext = ByteArray(((plaintextContent.bytes.size - 1) or 511) + 1)
                    System.arraycopy(
                        plaintextContent.bytes,
                        0,
                        paddedPlaintext,
                        0,
                        plaintextContent.bytes.size
                    )

                    // encrypt
                    try {
                        val authEnc = Suite.getAuthEnc(derivedKeysV2.encryptionKey)!!
                        encryptedBackup = authEnc.encrypt(
                            derivedKeysV2.encryptionKey,
                            paddedPlaintext,
                            backupManagerSession.prng!!
                        )
                    } catch (e: InvalidKeyException) {
                        // this never happens, but if the backup key does not work, retrying is useless!
                        Logger.x(e)
                        return BackupTaskStatus.PERMANENT_FAILURE
                    }

                    // compute the signature
                    val signaturePayload = Encoded.of(
                        arrayOf(
                            Encoded.of(derivedKeysV2.backupKeyUid),
                            Encoded.of(Constants.DEVICE_BACKUP_THREAD_ID),
                            Encoded.of(version),
                            Encoded.of(encryptedBackup),
                        )
                    ).bytes
                    signature = Signature.sign(
                        Constants.SignatureContext.BACKUP_UPLOAD,
                        signaturePayload,
                        derivedKeysV2.authenticationKeyPair.getPrivateKey().signaturePrivateKey,
                        backupManagerSession.prng
                    )
                }

                // 3.3 upload the snapshot to the server
                standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        null,
                        BackupsV2UploadBackupQuery(
                            server,
                            derivedKeysV2.backupKeyUid,
                            Constants.DEVICE_BACKUP_THREAD_ID,
                            version,
                            encryptedBackup,
                            signature
                        )
                    ), sslSocketFactory, userAgentOverride
                )
                queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-DeviceBackupUploadTask")
                queue.join()

                if (!standaloneServerQueryOperation.isFinished) {
                    // can be: general error, server parsing error, unknown backup uid, version too small, invalid signature
                    return BackupTaskStatus.RETRIABLE_FAILURE
                }
                return BackupTaskStatus.SUCCESS
            }
        } catch (e: Exception) {
            Logger.x(e)
            return BackupTaskStatus.RETRIABLE_FAILURE
        }
    }
}
