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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.containers.BackupsV2ListItem
import io.olvid.engine.datatypes.containers.BackupsV2ListItem.Companion.manyOf
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2CreateBackupQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2ListBackupsQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2UploadBackupQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvProfileBackupSnapshot
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import java.security.InvalidKeyException
import javax.net.ssl.SSLSocketFactory


class ProfileBackupUploadTask(
    private val backupManagerSessionFactory: BackupManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val ownedIdentity: Identity
) {
    fun execute(): BackupTaskStatus {
        try {
            backupManagerSessionFactory.session.use { backupManagerSession ->
                // if there is no device backup seed active, never upload a profile backup
                val deviceBackupSeed: DeviceBackupSeed? =
                    DeviceBackupSeed.getActive(backupManagerSession)
                if (deviceBackupSeed == null) {
                    Logger.w("ProfileBackupUploadTask no active DeviceBackupSeed")
                    return BackupTaskStatus.PERMANENT_FAILURE
                }

                var profileBackupThreadId: ProfileBackupThreadId? =
                    ProfileBackupThreadId.get(backupManagerSession, ownedIdentity)
                if (profileBackupThreadId == null) {
                    // we do not have a profileBackupThreadId yet (this can happen after creating a profile)
                    profileBackupThreadId = ProfileBackupThreadId.create(
                        backupManagerSession,
                        ownedIdentity,
                        backupManagerSession.prng!!
                    )
                    if (profileBackupThreadId != null) {
                        backupManagerSession.session.commit()
                    } else {
                        Logger.w("ProfileBackupUploadTask could not create a ProfileBackupThreadId for the given OwnedIdentity")
                        // this should only happen after deleting an OwnedIdentity
                        return BackupTaskStatus.RETRIABLE_FAILURE
                    }
                }

                val server = ownedIdentity.server
                if (!backupManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                        backupManagerSession.session,
                        ownedIdentity
                    )
                ) {
                    Logger.w("ProfileBackupUploadTask started for an inactive OwnedIdentity")
                    // never backup a profile that is not active
                    return BackupTaskStatus.PERMANENT_FAILURE
                }
                val backupSeed = backupManagerSession.identityDelegate.getOwnedIdentityBackupSeed(
                    backupManagerSession.session,
                    ownedIdentity
                )
                if (backupSeed == null) {
                    Logger.w("ProfileBackupUploadTask could not find a BackupSeed for the given OwnedIdentity")
                    // this should only happen after deleting an OwnedIdentity
                    return BackupTaskStatus.PERMANENT_FAILURE
                }
                val derivedKeysV2 = backupSeed.deriveKeysV2()


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
                queue.execute(1, "Engine-ProfileBackupUploadTask")
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
                        if (backupsV2ListItem.threadId == profileBackupThreadId.threadId) {
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
                    queue.execute(1, "Engine-ProfileBackupUploadTask")
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
                // 3. increment version number and upload a new profile backup
                version++

                // 3.1 create the snapshot
                var profileBackupSnapshot: ObvProfileBackupSnapshot?
                try {
                    backupManagerSession.session.startTransaction()
                    val identityBackupAndSyncDelegate =
                        backupManagerSession.identityDelegate.getSyncDelegateWithinTransaction(
                            backupManagerSession.session
                        )
                    profileBackupSnapshot = ObvProfileBackupSnapshot.get(
                        ownedIdentity,
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
                        profileBackupSnapshot.toEncodedDictionary(
                            backupManagerSession.identityDelegate.syncDelegate,
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
                        arrayOf<Encoded>(
                            Encoded.of(derivedKeysV2.backupKeyUid),
                            Encoded.of(profileBackupThreadId.threadId),
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
                            profileBackupThreadId.threadId,
                            version,
                            encryptedBackup,
                            signature
                        )
                    ), sslSocketFactory, userAgentOverride
                )
                queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-ProfileBackupUploadTask")
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
