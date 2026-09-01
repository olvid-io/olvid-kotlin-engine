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
package io.olvid.engine.networkfetch.coordinators

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.PutUserDataQuery
import io.olvid.engine.datatypes.containers.UserData
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networkfetch.databases.PendingServerQuery
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.operations.DeleteUserDataOperation
import io.olvid.engine.networkfetch.operations.RefreshUserDataOperation
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory

class ServerUserDataCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate,
    jsonObjectMapper: ObjectMapper,
    prng: PRNGService
) : OnCancelCallback, OnFinishCallback {
    private val jsonObjectMapper: ObjectMapper
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val createServerSessionDelegate: CreateServerSessionDelegate
    private val prng: PRNGService

    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUid?>
    private val deleteUserDataOperationQueue: NoDuplicateOperationQueue
    private val refreshUserDataOperationQueue: NoDuplicateOperationQueue

    private val awaitingServerSessionDeleteOperations: HashMap<Identity?, MutableList<UID?>?>
    private val awaitingServerSessionDeleteOperationsLock: Lock
    private val awaitingServerSessionRefreshOperations: HashMap<Identity?, MutableList<UID?>?>
    private val awaitingServerSessionRefreshOperationsLock: Lock
    private val notificationListener: NotificationListener

    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.createServerSessionDelegate = createServerSessionDelegate
        this.jsonObjectMapper = jsonObjectMapper
        this.prng = prng

        deleteUserDataOperationQueue = NoDuplicateOperationQueue()
        refreshUserDataOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUid?>()

        awaitingServerSessionDeleteOperations = HashMap<Identity?, MutableList<UID?>?>()
        awaitingServerSessionDeleteOperationsLock = ReentrantLock()
        awaitingServerSessionRefreshOperations = HashMap<Identity?, MutableList<UID?>?>()
        awaitingServerSessionRefreshOperationsLock = ReentrantLock()

        notificationListener = NotificationListener()
    }

    fun startProcessing() {
        deleteUserDataOperationQueue.execute(1, "Engine-ServerUserDataCoordinator-delete")
        refreshUserDataOperationQueue.execute(1, "Engine-ServerUserDataCoordinator-refresh")
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            notificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED,
            notificationListener
        )
    }


    fun initialQueueing() {
        // check all ServerUserData
        // delete no longer useful ServerUserData, refresh those that need it
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val userDataList: Array<UserData?>? =
                    fetchManagerSession.identityDelegate!!.getAllUserData(fetchManagerSession.session)
                for (userData in userDataList ?: return@use) {
                    if (userData == null) continue
                    when (userData.type) {
                        UserData.Type.OWNED_IDENTITY -> {
                            val details =
                                fetchManagerSession.identityDelegate.getOwnedIdentityPublishedDetails(
                                    fetchManagerSession.session,
                                    userData.ownedIdentity
                                )
                            if (details == null || !details.photoServerLabel
                                    .contentEquals(userData.label!!.bytes)
                            ) {
                                queueNewDeleteUserDataOperation(
                                    userData.ownedIdentity,
                                    userData.label
                                )
                            } else if (userData.nextRefreshTimestamp < System.currentTimeMillis()) {
                                queueNewRefreshUserDataOperation(
                                    userData.ownedIdentity,
                                    userData.label
                                )
                            } else {
                                scheduler.schedule(
                                    IdentityAndUid(
                                        userData.ownedIdentity!!,
                                        userData.label
                                    ),
                                    Runnable {
                                        queueNewRefreshUserDataOperation(
                                            userData.ownedIdentity,
                                            userData.label
                                        )
                                    },
                                    "ServerQueryOperation",
                                    userData.nextRefreshTimestamp - System.currentTimeMillis()
                                )
                            }
                        }

                        UserData.Type.GROUP -> {
                            val groupInformation =
                                fetchManagerSession.identityDelegate.getGroupInformation(
                                    fetchManagerSession.session,
                                    userData.ownedIdentity,
                                    userData.bytesGroupOwnerAndUidOrIdentifier
                                )
                            if (groupInformation == null ||  // group not found
                                !groupInformation.groupOwnerIdentity.equals(userData.ownedIdentity)
                            ) { // group not owned
                                queueNewDeleteUserDataOperation(
                                    userData.ownedIdentity,
                                    userData.label
                                )
                            } else {
                                try {
                                    val detailsWithVersionAndPhoto =
                                        jsonObjectMapper.readValue<JsonGroupDetailsWithVersionAndPhoto?>(
                                            groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                                            JsonGroupDetailsWithVersionAndPhoto::class.java
                                        )
                                    if (detailsWithVersionAndPhoto == null || !detailsWithVersionAndPhoto.photoServerLabel
                                            .contentEquals(userData.label!!.bytes)
                                    ) {
                                        queueNewDeleteUserDataOperation(
                                            userData.ownedIdentity,
                                            userData.label
                                        )
                                    } else if (userData.nextRefreshTimestamp < System.currentTimeMillis()) {
                                        queueNewRefreshUserDataOperation(
                                            userData.ownedIdentity,
                                            userData.label
                                        )
                                    } else {
                                        scheduler.schedule(
                                            IdentityAndUid(
                                                userData.ownedIdentity!!,
                                                userData.label
                                            ),
                                            Runnable {
                                                queueNewRefreshUserDataOperation(
                                                    userData.ownedIdentity,
                                                    userData.label
                                                )
                                            },
                                            "ServerQueryOperation",
                                            userData.nextRefreshTimestamp - System.currentTimeMillis()
                                        )
                                    }
                                } catch (_: Exception) {
                                    queueNewDeleteUserDataOperation(
                                        userData.ownedIdentity,
                                        userData.label
                                    )
                                }
                            }
                        }

                        UserData.Type.GROUP_V2 -> {
                            val serverPhotoInfo =
                                fetchManagerSession.identityDelegate.getGroupV2PublishedServerPhotoInfo(
                                    fetchManagerSession.session,
                                    userData.ownedIdentity,
                                    userData.bytesGroupOwnerAndUidOrIdentifier
                                )
                            if (serverPhotoInfo == null || (userData.ownedIdentity != serverPhotoInfo.serverPhotoIdentity) || (userData.label != serverPhotoInfo.serverPhotoLabel)) { // photo changed
                                queueNewDeleteUserDataOperation(
                                    userData.ownedIdentity,
                                    userData.label
                                )
                            } else if (userData.nextRefreshTimestamp < System.currentTimeMillis()) {
                                queueNewRefreshUserDataOperation(
                                    userData.ownedIdentity,
                                    userData.label
                                )
                            } else {
                                scheduler.schedule(
                                    IdentityAndUid(
                                        userData.ownedIdentity!!,
                                        userData.label
                                    ),
                                    Runnable {
                                        queueNewRefreshUserDataOperation(
                                            userData.ownedIdentity,
                                            userData.label
                                        )
                                    },
                                    "ServerQueryOperation",
                                    userData.nextRefreshTimestamp - System.currentTimeMillis()
                                )
                            }
                        }

                        else -> {}
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // cleanup downloaded user data dir of orphan files
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val userDataDir = fetchManagerSession.fileIo.file(
                    fetchManagerSession.engineBaseDirectory,
                    Constants.DOWNLOADED_USER_DATA_DIRECTORY
                )
                val userDataFiles = userDataDir.listDirectory()
                if (userDataFiles != null) {
                    for (userDataFile in userDataFiles.managedFileList) {
                        val pos = userDataFile.plainNameFile.name.indexOf(".")
                        if (pos != -1) {
                            val expireTimestamp =
                                userDataFile.plainNameFile.name.substring(0, pos).toLong()
                            if (expireTimestamp > System.currentTimeMillis()) {
                                continue
                            }
                        }
                        // the . is missing, or the file is expired --> delete it
                        try {
                            userDataFile.delete()
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    private fun queueNewRefreshUserDataOperation(ownedIdentity: Identity?, label: UID?) {
        if (ownedIdentity == null || label == null) return
        val op = RefreshUserDataOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            label,
            this,
            this
        )
        refreshUserDataOperationQueue.queue(op)
    }

    private fun scheduleNewRefreshUserDataOperation(ownedIdentity: Identity, label: UID) {
        scheduler.schedule(
            IdentityAndUid(ownedIdentity, label),
            Runnable { queueNewRefreshUserDataOperation(ownedIdentity, label) },
            "RefreshUserDataOperation"
        )
    }


    private fun queueNewDeleteUserDataOperation(ownedIdentity: Identity?, label: UID?) {
        if (ownedIdentity == null || label == null) return
        val op = DeleteUserDataOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            label,
            this,
            this
        )
        deleteUserDataOperationQueue.queue(op)
    }

    private fun scheduleNewDeleteUserDataOperation(ownedIdentity: Identity, label: UID) {
        scheduler.schedule(
            IdentityAndUid(ownedIdentity, label),
            Runnable { queueNewDeleteUserDataOperation(ownedIdentity, label) },
            "DeleteUserDataOperation"
        )
    }

    private fun deleteWaitForServerSession(identity: Identity?, label: UID?) {
        awaitingServerSessionDeleteOperationsLock.lock()
        var list = awaitingServerSessionDeleteOperations.get(identity)
        if (list == null) {
            list = ArrayList<UID?>()
            awaitingServerSessionDeleteOperations.put(identity, list)
        }
        list.add(label)
        awaitingServerSessionDeleteOperationsLock.unlock()
    }

    private fun refreshWaitForServerSession(identity: Identity?, label: UID?) {
        awaitingServerSessionRefreshOperationsLock.lock()
        var list = awaitingServerSessionRefreshOperations.get(identity)
        if (list == null) {
            list = ArrayList<UID?>()
            awaitingServerSessionRefreshOperations.put(identity, list)
        }
        list.add(label)
        awaitingServerSessionRefreshOperationsLock.unlock()
    }


    override fun onCancelCallback(operation: Operation) {
        if (operation is RefreshUserDataOperation) {
            val ownedIdentity = operation.ownedIdentity
            val label = operation.label
            var rfc = operation.reasonForCancel
            Logger.d("RefreshUserDataOperation cancelled for reason " + rfc)
            if (rfc == null) {
                rfc = Operation.RFC_NULL
            }
            when (rfc) {
                RefreshUserDataOperation.RFC_INVALID_SERVER_SESSION -> {
                    refreshWaitForServerSession(ownedIdentity, label)
                    createServerSessionDelegate.createServerSession(ownedIdentity)
                }

                RefreshUserDataOperation.RFC_USER_DATA_DELETED_FROM_SERVER -> {
                    // create a new server query, not linked to a protocol
                    try {
                        fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                            val userData = fetchManagerSession.identityDelegate!!.getUserData(
                                fetchManagerSession.session,
                                ownedIdentity,
                                label
                            )
                            if (userData != null) {
                                val photoUrl: String?
                                val key: AuthEncKey?

                                when (userData.type) {
                                    UserData.Type.OWNED_IDENTITY -> {
                                        val json =
                                            fetchManagerSession.identityDelegate.getOwnedIdentityPublishedDetails(
                                                fetchManagerSession.session,
                                                userData.ownedIdentity
                                            )
                                        photoUrl = json!!.photoUrl
                                        key =
                                            Encoded(json.photoServerKey!!).decodeSymmetricKey() as AuthEncKey?
                                    }

                                    UserData.Type.GROUP -> {
                                        val json: JsonGroupDetailsWithVersionAndPhoto =
                                            fetchManagerSession.identityDelegate.getGroupPublishedAndLatestOrTrustedDetails(
                                                fetchManagerSession.session,
                                                userData.ownedIdentity,
                                                userData.bytesGroupOwnerAndUidOrIdentifier
                                            )!![0]!!
                                        photoUrl = json.getPhotoUrl()
                                        key =
                                            Encoded(json.getPhotoServerKey()!!).decodeSymmetricKey() as AuthEncKey?
                                    }

                                    UserData.Type.GROUP_V2 -> {
                                        val serverPhotoInfo =
                                            fetchManagerSession.identityDelegate.getGroupV2PublishedServerPhotoInfo(
                                                fetchManagerSession.session,
                                                userData.ownedIdentity,
                                                userData.bytesGroupOwnerAndUidOrIdentifier
                                            )
                                        photoUrl =
                                            fetchManagerSession.identityDelegate.getGroupV2PhotoUrl(
                                                fetchManagerSession.session,
                                                userData.ownedIdentity,
                                                GroupV2.Identifier.of(userData.bytesGroupOwnerAndUidOrIdentifier!!)
                                            )
                                        key = serverPhotoInfo!!.serverPhotoKey
                                    }

                                    else -> {
                                        photoUrl = null
                                        key = null
                                    }
                                }

                                if (photoUrl != null && key != null) {
                                    val serverQuery = ServerQuery(
                                        Encoded.of(emptyArray<Encoded>()),
                                        ownedIdentity,
                                        PutUserDataQuery(ownedIdentity, label, photoUrl, key)
                                    )

                                    PendingServerQuery.create(
                                        fetchManagerSession,
                                        serverQuery,
                                        prng
                                    )
                                    fetchManagerSession.session.commit()
                                }
                            }
                        }
                    } catch (e: Exception) {
                        // do nothing, this will be retried after the next restart
                        Logger.x(e)
                    }
                }

                RefreshUserDataOperation.RFC_IDENTITY_IS_INACTIVE, RefreshUserDataOperation.RFC_USER_DATA_NOT_FOUND -> {}
                else ->                     // Requeue the operation in the future
                    scheduleNewRefreshUserDataOperation(ownedIdentity, label)
            }
        } else if (operation is DeleteUserDataOperation) {
            val ownedIdentity = operation.ownedIdentity
            val label = operation.label
            var rfc = operation.reasonForCancel
            Logger.i("DeleteUserDataOperation cancelled for reason " + rfc)
            if (rfc == null) {
                rfc = Operation.RFC_NULL
            }
            when (rfc) {
                DeleteUserDataOperation.RFC_INVALID_SERVER_SESSION -> {
                    deleteWaitForServerSession(ownedIdentity, label)
                    createServerSessionDelegate.createServerSession(ownedIdentity)
                }

                DeleteUserDataOperation.RFC_IDENTITY_IS_INACTIVE, DeleteUserDataOperation.RFC_USER_DATA_NOT_FOUND -> {}
                else ->                     // Requeue the operation in the future
                    scheduleNewDeleteUserDataOperation(ownedIdentity, label)
            }
        }
    }

    override fun onFinishCallback(operation: Operation) {
        if (operation is RefreshUserDataOperation) {
            Logger.d("RefreshUserDataOperation finished")
            val ownedIdentity = operation.ownedIdentity
            val label = operation.label
            scheduler.clearFailedCount(IdentityAndUid(ownedIdentity, label))
            newUserDataUploaded(ownedIdentity, label)
        } else if (operation is DeleteUserDataOperation) {
            Logger.d("DeleteUserDataOperation finished")
            val ownedIdentity = operation.ownedIdentity
            val label = operation.label
            scheduler.clearFailedCount(IdentityAndUid(ownedIdentity, label))
        }
    }

    fun newUserDataUploaded(ownedIdentity: Identity, label: UID) {
        scheduler.schedule(
            IdentityAndUid(ownedIdentity, label),
            Runnable { queueNewRefreshUserDataOperation(ownedIdentity, label) },
            "ServerQueryOperation",
            Constants.USER_DATA_REFRESH_INTERVAL
        )
    }

    internal inner class NotificationListener : io.olvid.engine.datatypes.NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            try {
                when (notificationName) {
                    DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED -> {
                        val ownedIdentity =
                            userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY) as Identity?
                        awaitingServerSessionDeleteOperationsLock.lock()
                        var labels = awaitingServerSessionDeleteOperations.get(ownedIdentity)
                        if (labels != null) {
                            awaitingServerSessionDeleteOperations.remove(ownedIdentity)
                            for (label in labels) {
                                queueNewDeleteUserDataOperation(ownedIdentity, label)
                            }
                        }
                        awaitingServerSessionDeleteOperationsLock.unlock()

                        awaitingServerSessionRefreshOperationsLock.lock()
                        labels = awaitingServerSessionRefreshOperations.get(ownedIdentity)
                        if (labels != null) {
                            awaitingServerSessionRefreshOperations.remove(ownedIdentity)
                            for (label in labels) {
                                queueNewRefreshUserDataOperation(ownedIdentity, label)
                            }
                        }
                        awaitingServerSessionRefreshOperationsLock.unlock()
                    }

                    IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED -> {
                        val ownedIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_OWNED_IDENTITY_KEY) as Identity?
                        val label =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_LABEL_KEY) as UID?
                        if (ownedIdentity != null && label != null) {
                            queueNewDeleteUserDataOperation(ownedIdentity, label)
                        }
                    }
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
    }
}
