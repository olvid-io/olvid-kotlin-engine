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
import io.olvid.engine.backup.databases.ProfileBackupThreadId
import io.olvid.engine.backup.datatypes.BackupManagerSessionFactory
import io.olvid.engine.backup.datatypes.BackupTaskStatus
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.BackupsV2ListItem
import io.olvid.engine.datatypes.containers.BackupsV2ListItem.Companion.manyOf
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2ListBackupsQuery
import io.olvid.engine.datatypes.containers.ServerQuery.OwnedDeviceDiscoveryQuery
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvDeviceList
import io.olvid.engine.engine.types.ObvProfileBackupsForRestore
import io.olvid.engine.engine.types.ObvProfileBackupsForRestore.ObvProfileBackupForRestore
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.IdBased
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.OpenIdConnect
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.engine.types.sync.ObvProfileBackupSnapshot
import io.olvid.engine.identity.databases.sync.IdentityManagerSyncSnapshot
import io.olvid.engine.identity.databases.sync.OwnedIdentitySyncSnapshot
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import java.util.function.ToLongFunction
import javax.net.ssl.SSLSocketFactory


class ProfileBackupsFetchTask(
    private val server: String?,
    private val profileBackupSeed: BackupSeed,
    private val backupManagerSessionFactory: BackupManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?
) {
    var obvProfileBackupsForRestore: ObvProfileBackupsForRestore? = null
        private set

    fun execute(): BackupTaskStatus {
        val derivedKeysV2 = profileBackupSeed.deriveKeysV2()

        /**//// */
        // 1. list profile backups
        var standaloneServerQueryOperation = StandaloneServerQueryOperation(
            ServerQuery(
                null,
                null,
                BackupsV2ListBackupsQuery(server, derivedKeysV2.backupKeyUid)
            ), sslSocketFactory, userAgentOverride
        )
        var queue = OperationQueue()
        queue.queue(standaloneServerQueryOperation)
        queue.execute(1, "Engine-ProfileBackupsFetchTask")
        queue.join()

        val profilesToDownload: MutableList<BackupsV2ListItem> = ArrayList()

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
                    continue
                }
                profilesToDownload.add(backupsV2ListItem)
            }
        } else {
            val rfc = standaloneServerQueryOperation.reasonForCancel
            if (rfc == null) {
                return BackupTaskStatus.RETRIABLE_FAILURE
            } else if (rfc == StandaloneServerQueryOperation.RFC_NETWORK_ERROR) {
                obvProfileBackupsForRestore = ObvProfileBackupsForRestore(
                    ObvProfileBackupsForRestore.Status.NETWORK_ERROR,
                    null,
                    null
                )
                return BackupTaskStatus.RETRIABLE_FAILURE
            } else if (rfc != StandaloneServerQueryOperation.RFC_UNKNOWN_BACKUP_UID) {
                // can be: general error, server parsing error
                return BackupTaskStatus.RETRIABLE_FAILURE
            }
        }


        val identityDelegate: IdentityDelegate?
        val appBackupAndSyncDelegates: ObvBackupAndSyncDelegate?
        val thisDeviceThreadIds = HashMap<Identity?, UID?>()

        try {
            backupManagerSessionFactory.session.use { backupManagerSession ->
                identityDelegate = backupManagerSession.identityDelegate
                appBackupAndSyncDelegates = backupManagerSession.appBackupAndSyncDelegate
                for (profileBackupThreadId in ProfileBackupThreadId.getAll(
                    backupManagerSession
                )) {
                    thisDeviceThreadIds[profileBackupThreadId.ownedIdentity] = profileBackupThreadId.threadId
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
            return BackupTaskStatus.RETRIABLE_FAILURE
        }


        /**/// */
        // 3. download and decrypt the backup files
        val profileBackupsForRestore: MutableList<ObvProfileBackupForRestore?> =
            ArrayList()
        var truncated = false
        var privateIdentity: OwnedIdentitySyncSnapshot.PrivateIdentity? = null
        var bytesIdentity: ByteArray? = null

        for (profileToDownload in profilesToDownload) { /**///// */
            // 3.1. download
            val serverMethod = DownloadBackupFromServer(profileToDownload.downloadUrl)
            if (!serverMethod.execute()) {
                truncated = true
                continue
            }

            /**///// */
            // 3.2. decrypt the encrypted profile backup
            val obvProfileBackupSnapshot: ObvProfileBackupSnapshot?
            try {
                val encryptedBackup = EncryptedBytes(serverMethod.encryptedBackup!!)

                // decrypt
                val authEnc = Suite.getAuthEnc(derivedKeysV2.encryptionKey)!!
                val paddedPlaintext = authEnc.decrypt(derivedKeysV2.encryptionKey, encryptedBackup)!!

                // decode
                val encodedDictionary: HashMap<DictionaryKey, Encoded> =
                    Encoded(paddedPlaintext).decodeDictionaryWithPadding()

                obvProfileBackupSnapshot = ObvProfileBackupSnapshot.fromEncodedDictionary(
                    encodedDictionary,
                    identityDelegate!!.syncDelegate,
                    appBackupAndSyncDelegates
                )
            } catch (e: Exception) {
                // if the backup cannot be decrypted or decoded, no need to retry
                Logger.x(e)
                truncated = true
                continue
            }
            if (obvProfileBackupSnapshot == null) {
                truncated = true
                continue
            }

            /**/////// */
            // 3.3. convert the ObvProfileBackupSnapshot to an ObvProfileBackupForRestore
            val obvProfileBackupForRestore = ObvProfileBackupForRestore()
            obvProfileBackupForRestore.bytesBackupThreadId = profileToDownload.threadId!!.bytes
            obvProfileBackupForRestore.version = profileToDownload.version
            obvProfileBackupForRestore.timestamp = obvProfileBackupSnapshot.getTimestamp()
            obvProfileBackupForRestore.additionalInfo = obvProfileBackupSnapshot.getAdditionalInfo()
            obvProfileBackupForRestore.snapshot = obvProfileBackupSnapshot.getSnapshot()

            val obvSyncSnapshotNode =
                obvProfileBackupForRestore.snapshot!!.getSnapshotNode(identityDelegate.syncDelegate!!.tag)
            if (obvSyncSnapshotNode is IdentityManagerSyncSnapshot) {
                val ownedIdentityNode = obvSyncSnapshotNode.owned_identity_node!!

                if (privateIdentity == null) {
                    privateIdentity = ownedIdentityNode.private_identity
                    bytesIdentity = obvSyncSnapshotNode.owned_identity
                }

                obvProfileBackupForRestore.contactCount = ownedIdentityNode.contacts?.size ?: 0
                obvProfileBackupForRestore.groupCount =
                    (ownedIdentityNode.groups?.size ?: 0) + (ownedIdentityNode.groups2?.size ?: 0)

                try {
                    obvProfileBackupForRestore.fromThisDevice =
                        profileToDownload.threadId == thisDeviceThreadIds[Identity.of(obvSyncSnapshotNode.owned_identity!!)]
                } catch (e: Exception) {
                    Logger.x(e)
                    obvProfileBackupForRestore.fromThisDevice = false
                }
                val keycloak = ownedIdentityNode.keycloak
                if (keycloak != null) {
                    if (keycloak.transfer_restricted) {
                        obvProfileBackupForRestore.keycloakStatus =
                            ObvProfileBackupsForRestore.KeycloakStatus.TRANSFER_RESTRICTED
                    } else {
                        obvProfileBackupForRestore.keycloakStatus =
                            ObvProfileBackupsForRestore.KeycloakStatus.MANAGED
                    }
                    obvProfileBackupForRestore.keycloakServerUrl =
                        keycloak.server_url
                    obvProfileBackupForRestore.supportedAuthenticationMethods =
                        ArrayList()
                    if (keycloak.client_id != null) {
                        obvProfileBackupForRestore.supportedAuthenticationMethods!!.add(
                            OpenIdConnect(
                                keycloak.client_id,
                                keycloak.client_secret
                            )
                        )
                    }
                    if (keycloak.supports_id_based_auth) {
                        obvProfileBackupForRestore.supportedAuthenticationMethods!!.add(IdBased())
                    }
                } else {
                    obvProfileBackupForRestore.keycloakStatus =
                        ObvProfileBackupsForRestore.KeycloakStatus.UNMANAGED
                    obvProfileBackupForRestore.keycloakServerUrl = null
                    obvProfileBackupForRestore.supportedAuthenticationMethods = mutableListOf()
                }
            } else {
                truncated = true
                continue
            }

            profileBackupsForRestore.add(obvProfileBackupForRestore)
        }

        profileBackupsForRestore.sortWith(
            Comparator.comparingLong<ObvProfileBackupForRestore?>(
                ToLongFunction { o: ObvProfileBackupForRestore? -> -o!!.timestamp })
        )

        var deviceList: ObvDeviceList? = null
        val pi = privateIdentity
        if (pi != null) {
            try {
                val identity = Identity.of(bytesIdentity!!)
                val privateKey =
                    Encoded(pi.encryption_private_key!!).decodePrivateKey() as EncryptionPrivateKey?

                standaloneServerQueryOperation = StandaloneServerQueryOperation(
                    ServerQuery(
                        null,
                        identity,
                        OwnedDeviceDiscoveryQuery(identity)
                    ), sslSocketFactory, userAgentOverride
                )

                queue = OperationQueue()
                queue.queue(standaloneServerQueryOperation)
                queue.execute(1, "Engine-ProfileBackupsFetchTask")
                queue.join()

                if (standaloneServerQueryOperation.isFinished && standaloneServerQueryOperation.serverResponse != null) {
                    deviceList = ObvDeviceList.of(
                        standaloneServerQueryOperation.serverResponse!!.decodeEncryptedData(),
                        privateKey
                    )
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }

        obvProfileBackupsForRestore = ObvProfileBackupsForRestore(
            if (truncated) ObvProfileBackupsForRestore.Status.TRUNCATED else ObvProfileBackupsForRestore.Status.SUCCESS,
            profileBackupsForRestore,
            deviceList
        )

        return BackupTaskStatus.SUCCESS
    }
}
