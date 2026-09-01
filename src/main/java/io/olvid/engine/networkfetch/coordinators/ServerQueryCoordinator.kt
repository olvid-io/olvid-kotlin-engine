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
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelServerResponseMessageToSend
import io.olvid.engine.datatypes.containers.ServerQuery.PutUserDataQuery
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.metamanager.ChannelDelegate
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networkfetch.databases.PendingServerQuery
import io.olvid.engine.networkfetch.databases.PendingServerQuery.PendingServerQueryListener
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.operations.ServerQueryOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory

class ServerQueryCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    prng: PRNGService,
    createServerSessionDelegate: CreateServerSessionDelegate,
    serverUserDataCoordinator: ServerUserDataCoordinator,
    jsonObjectMapper: ObjectMapper?
) : PendingServerQueryListener, OnCancelCallback, OnFinishCallback {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val prng: PRNGService
    private val createServerSessionDelegate: CreateServerSessionDelegate

    private val webSocketModule: ServerQueryCoordinatorWebSocketModule
    private val scheduler: ExponentialBackoffRepeatingScheduler<UID?>
    private val serverQueriesOperationQueue: NoDuplicateOperationQueue

    private val awaitingServerSessionOperations: HashMap<Identity?, MutableList<UID?>?>
    private val awaitingServerSessionOperationsLock: Lock
    private val notificationListener: NotificationListener
    private val serverUserDataCoordinator: ServerUserDataCoordinator

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<UID?>?>
    private val awaitingIdentityReactivationOperationsLock: Lock

    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    private var channelDelegate: ChannelDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.prng = prng
        this.createServerSessionDelegate = createServerSessionDelegate
        this.serverUserDataCoordinator = serverUserDataCoordinator

        webSocketModule = ServerQueryCoordinatorWebSocketModule(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            jsonObjectMapper,
            prng
        )

        serverQueriesOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<UID?>()

        awaitingServerSessionOperations = HashMap<Identity?, MutableList<UID?>?>()
        awaitingServerSessionOperationsLock = ReentrantLock()

        awaitingIdentityReactivationOperations = HashMap<Identity?, MutableList<UID?>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()

        notificationListener = NotificationListener()
    }

    fun startProcessing() {
        serverQueriesOperationQueue.execute(1, "Engine-ServerQueryCoordinator")
    }

    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val pendingServerQueries: Array<PendingServerQuery?> =
                    PendingServerQuery.getAll(fetchManagerSession)
                for (pendingServerQuery in pendingServerQueries) {
                    if (pendingServerQuery == null) continue
                    if (pendingServerQuery.isWebSocket) {
                        pendingServerQuery.delete()
                    } else {
                        queueNewServerQueryOperation(pendingServerQuery.uid)
                    }
                }
                // commit, in case a WebSocket query was deleted
                fetchManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            notificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            notificationListener
        )
    }

    fun setChannelDelegate(channelDelegate: ChannelDelegate?) {
        this.channelDelegate = channelDelegate
        if (channelDelegate != null) {
            webSocketModule.setChannelDelegate(channelDelegate)
        }
    }

    private fun waitForServerSession(identity: Identity?, serverQueryUid: UID?) {
        awaitingServerSessionOperationsLock.lock()
        var list = awaitingServerSessionOperations.get(identity)
        if (list == null) {
            list = ArrayList<UID?>()
            awaitingServerSessionOperations.put(identity, list)
        }
        list.add(serverQueryUid)
        awaitingServerSessionOperationsLock.unlock()
    }

    private fun waitForIdentityReactivation(identity: Identity?, serverQueryUid: UID?) {
        awaitingIdentityReactivationOperationsLock.lock()
        var list = awaitingIdentityReactivationOperations.get(identity)
        if (list == null) {
            list = ArrayList<UID?>()
            awaitingIdentityReactivationOperations.put(identity, list)
        }
        list.add(serverQueryUid)
        awaitingIdentityReactivationOperationsLock.unlock()
    }

    internal inner class NotificationListener : io.olvid.engine.datatypes.NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            try {
                when (notificationName) {
                    IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS -> {
                        val active =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_ACTIVE_KEY) as? Boolean ?: return
                        val ownedIdentity =
                            userInfo[IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_OWNED_IDENTITY_KEY] as Identity?
                        if (!active) {
                            return
                        }

                        awaitingIdentityReactivationOperationsLock.lock()
                        val serverQueryUids =
                            awaitingIdentityReactivationOperations.get(ownedIdentity)
                        if (serverQueryUids != null) {
                            awaitingIdentityReactivationOperations.remove(ownedIdentity)
                            for (serverQueryUid in serverQueryUids) {
                                queueNewServerQueryOperation(serverQueryUid)
                            }
                        }
                        awaitingIdentityReactivationOperationsLock.unlock()
                    }

                    DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED -> {
                        val ownedIdentity =
                            userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY) as Identity?
                        awaitingServerSessionOperationsLock.lock()
                        val serverQueryUids = awaitingServerSessionOperations.get(ownedIdentity)
                        if (serverQueryUids != null) {
                            awaitingServerSessionOperations.remove(ownedIdentity)
                            for (serverQueryUid in serverQueryUids) {
                                queueNewServerQueryOperation(serverQueryUid)
                            }
                        }
                        awaitingServerSessionOperationsLock.unlock()
                    }
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
    }

    private fun queueNewServerQueryOperation(serverQueryUid: UID?) {
        val op = ServerQueryOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            serverQueryUid,
            prng,
            this,
            this
        )
        serverQueriesOperationQueue.queue(op)
    }

    private fun scheduleNewServerQueryOperation(serverQueryUid: UID?) {
        scheduler.schedule(
            serverQueryUid,
            Runnable { queueNewServerQueryOperation(serverQueryUid) },
            "ServerQueryOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    override fun onCancelCallback(operation: Operation) {
        val serverQueryUid = (operation as ServerQueryOperation).serverQueryUid
        val serverQuery = operation.getServerQuery()
        var rfc = operation.reasonForCancel
        Logger.i("ServerQueryOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            ServerQueryOperation.RFC_MALFORMED_URL, ServerQueryOperation.RFC_USER_DATA_TOO_LARGE, ServerQueryOperation.RFC_BAD_ENCODED_SERVER_QUERY, ServerQueryOperation.RFC_DEVICE_DOES_NOT_EXIST -> {
                // PendingServerQuery cannot be understood,
                // or the data to send is too large
                // ==> we can delete it from the database
                try {
                    fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                        val pendingServerQuery: PendingServerQuery? =
                            PendingServerQuery.get(fetchManagerSession, serverQueryUid)
                        if (pendingServerQuery != null) {
                            pendingServerQuery.delete()
                            fetchManagerSession.session.commit()
                        }
                    }
                } catch (e: SQLException) {
                    Logger.x(e)
                }
            }

            ServerQueryOperation.RFC_INVALID_SERVER_SESSION -> {
                waitForServerSession(serverQuery.getOwnedIdentity(), serverQueryUid)
                createServerSessionDelegate.createServerSession(serverQuery.getOwnedIdentity())
            }

            ServerQueryOperation.RFC_IDENTITY_IS_INACTIVE -> {
                waitForIdentityReactivation(serverQuery.getOwnedIdentity(), serverQueryUid)
            }

            ServerQueryOperation.RFC_DEVICE_NOT_YET_REGISTERED -> {
                // Requeue the operation in the future
                scheduleNewServerQueryOperation(serverQueryUid)
            }

            else -> {
                scheduleNewServerQueryOperation(serverQueryUid)
            }
        }
    }

    override fun onFinishCallback(operation: Operation) {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val serverQueryUid = (operation as ServerQueryOperation).serverQueryUid
                val serverQuery = operation.getServerQuery()
                val serverResponse = operation.serverResponse

                scheduler.clearFailedCount(serverQueryUid)

                val pendingServerQuery: PendingServerQuery? =
                    PendingServerQuery.get(fetchManagerSession, serverQueryUid)
                if (pendingServerQuery == null) {
                    return
                }
                // check if the encoded elements are empty --> empty means no associated protocol
                var partOfProtocol = true
                try {
                    partOfProtocol = serverQuery.getEncodedElements()!!.decodeList().size != 0
                } catch (_: DecodingException) {
                    // do nothing
                }

                if (partOfProtocol) {
                    val channelServerResponseMessageToSend = ChannelServerResponseMessageToSend(
                        serverQuery.getOwnedIdentity(),
                        serverResponse,
                        serverQuery.getEncodedElements()
                    )
                    if (channelDelegate == null) {
                        Logger.e("ServerQueryOperation finished but no ChannelDelegate is set to post the response to.")
                        return
                    }
                    try {
                        fetchManagerSession.session.startTransaction()
                        try {
                            // NoAcceptableChannelException happen if owned identity was deleted
                            channelDelegate!!.post(
                                fetchManagerSession.session,
                                channelServerResponseMessageToSend,
                                prng
                            )
                        } catch (_: NoAcceptableChannelException) {
                        }
                        pendingServerQuery.delete()
                        fetchManagerSession.session.commit()
                    } catch (_: Exception) {
                        fetchManagerSession.session.rollback()
                    }
                } else {
                    pendingServerQuery.delete()
                    fetchManagerSession.session.commit()
                }
                if (serverQuery.getType() is PutUserDataQuery && serverQuery.getOwnedIdentity() != null) {
                    serverUserDataCoordinator.newUserDataUploaded(
                        serverQuery.getOwnedIdentity()!!,
                        (serverQuery.getType() as PutUserDataQuery).serverLabel
                    )
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }


    // Notifications received from PendingServerQuery database
    override fun newPendingServerQuery(pendingServerQuery: PendingServerQuery?) {
        if (pendingServerQuery == null) return
        if (pendingServerQuery.isWebSocket) {
            webSocketModule.handleServerQuery(pendingServerQuery, false)
        } else {
            queueNewServerQueryOperation(pendingServerQuery.uid)
        }
    }
}
