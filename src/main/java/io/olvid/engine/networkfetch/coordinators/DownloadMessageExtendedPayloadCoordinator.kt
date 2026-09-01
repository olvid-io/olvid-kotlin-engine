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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.databases.InboxMessage.ExtendedPayloadListener
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.operations.DownloadMessagesExtendedPayloadOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class DownloadMessageExtendedPayloadCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate
) : OnCancelCallback, OnFinishCallback, ExtendedPayloadListener {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val createServerSessionDelegate: CreateServerSessionDelegate

    private val scheduler: ExponentialBackoffRepeatingScheduler<Identity?>
    private val downloadMessagesExtendedPayloadOperationQueue: NoDuplicateOperationQueue

    private val awaitingNotificationListener: AwaitingNotificationListener

    private val awaitingServerSessionOperations: HashMap<Identity?, UID?>
    private val awaitingServerSessionOperationsLock: Lock

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<UID?>?>
    private val awaitingIdentityReactivationOperationsLock: Lock

    private var notificationListeningDelegate: NotificationListeningDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.createServerSessionDelegate = createServerSessionDelegate

        downloadMessagesExtendedPayloadOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler()
        awaitingNotificationListener = AwaitingNotificationListener()

        awaitingServerSessionOperations = HashMap()
        awaitingServerSessionOperationsLock = ReentrantLock()

        awaitingIdentityReactivationOperations = HashMap()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()
    }

    fun startProcessing() {
        downloadMessagesExtendedPayloadOperationQueue.execute(
            1,
            "Engine-DownloadMessagesExtendedPayloadCoordinator"
        )
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            awaitingNotificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            awaitingNotificationListener
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }


    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val extendedPayloadInboxMessages: Array<InboxMessage> =
                    InboxMessage.getExtendedPayloadMessages(fetchManagerSession)
                for (inboxMessage in extendedPayloadInboxMessages) {
                    messageExtendedPayloadDownloaded(
                        inboxMessage.getOwnedIdentity(),
                        inboxMessage.uid,
                        inboxMessage.getExtendedPayload()
                    )
                }

                val missingExtendedPayloadInboxMessages: Array<InboxMessage> =
                    InboxMessage.getMissingExtendedPayloadMessages(fetchManagerSession)
                for (inboxMessage in missingExtendedPayloadInboxMessages) {
                    messageHasExtendedPayloadToDownload(
                        inboxMessage.getOwnedIdentity(),
                        inboxMessage.uid
                    )
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun messageHasExtendedPayloadToDownload(ownedIdentity: Identity?, uid: UID?) {
        if (ownedIdentity != null) {
            queueNewDownloadMessagesExtendedPayloadOperation(ownedIdentity, uid)
        }
    }

    override fun messageExtendedPayloadDownloaded(
        ownedIdentity: Identity?,
        uid: UID?,
        extendedPayload: ByteArray?
    ) {
        if (notificationPostingDelegate != null) {
            val userInfo = HashMap<String, Any>()
            ownedIdentity?.let { userInfo[DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_OWNED_IDENTITY_KEY] = it }
            uid?.let { userInfo[DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_MESSAGE_UID_KEY] = it }
            extendedPayload?.let { userInfo[DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_EXTENDED_PAYLOAD_KEY] = it }
            notificationPostingDelegate?.postNotification(
                DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED,
                userInfo
            )
        }
    }


    private fun queueNewDownloadMessagesExtendedPayloadOperation(
        identity: Identity,
        messageUid: UID?
    ) {
        val op = DownloadMessagesExtendedPayloadOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            identity,
            messageUid,
            this,
            this
        )
        downloadMessagesExtendedPayloadOperationQueue.queue(op)
    }

    private fun scheduleNewDownloadMessagesExtendedPayloadOperationQueueing(
        identity: Identity,
        messageUid: UID?
    ) {
        scheduler.schedule(
            identity,
            { queueNewDownloadMessagesExtendedPayloadOperation(identity, messageUid) },
            "DownloadMessagesExtendedPayloadOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    private fun waitForServerSession(identity: Identity?, deviceUid: UID?) {
        awaitingServerSessionOperationsLock.lock()
        awaitingServerSessionOperations[identity] = deviceUid
        awaitingServerSessionOperationsLock.unlock()
    }

    private fun waitForIdentityReactivation(ownedIdentity: Identity?, messageUid: UID?) {
        awaitingIdentityReactivationOperationsLock.lock()
        var list = awaitingIdentityReactivationOperations[ownedIdentity]
        if (list == null) {
            list = ArrayList()
            awaitingIdentityReactivationOperations[ownedIdentity] = list
        }
        list.add(messageUid)
        awaitingIdentityReactivationOperationsLock.unlock()
    }


    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity =
            (operation as DownloadMessagesExtendedPayloadOperation).ownedIdentity
        scheduler.clearFailedCount(ownedIdentity)
    }

    override fun onCancelCallback(operation: Operation) {
        if (operation is DownloadMessagesExtendedPayloadOperation) {
            val ownedIdentity = operation.ownedIdentity
            val messageUid = operation.messageUid
            var rfc = operation.reasonForCancel
            Logger.i("DownloadMessagesExtendedPayloadOperation cancelled for reason $rfc")
            if (rfc == null) {
                rfc = Operation.RFC_NULL
            }
            when (rfc) {
                DownloadMessagesExtendedPayloadOperation.RFC_EXTENDED_PAYLOAD_UNAVAILABLE_OR_INVALID -> {
                    try {
                        fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                            // mark the message as not having an extended payload
                            if (messageUid != null) {
                                InboxMessage.clearExtendedPayload(
                                    fetchManagerSession,
                                    ownedIdentity,
                                    messageUid
                                )
                            }
                        }
                    } catch (_: SQLException) {
                        // do nothing
                    }
                }

                DownloadMessagesExtendedPayloadOperation.RFC_IDENTITY_IS_INACTIVE -> {
                    // wait for identity to become active again
                    waitForIdentityReactivation(ownedIdentity, messageUid)
                }

                DownloadMessagesExtendedPayloadOperation.RFC_INVALID_SERVER_SESSION -> {
                    waitForServerSession(ownedIdentity, messageUid)
                    createServerSessionDelegate.createServerSession(ownedIdentity)
                }

                DownloadMessagesExtendedPayloadOperation.RFC_MESSAGE_CANNOT_BE_FOUND -> {}
                DownloadMessagesExtendedPayloadOperation.RFC_NETWORK_ERROR -> {
                    scheduleNewDownloadMessagesExtendedPayloadOperationQueueing(
                        ownedIdentity,
                        messageUid
                    )
                }

                else -> {
                    scheduleNewDownloadMessagesExtendedPayloadOperationQueueing(
                        ownedIdentity,
                        messageUid
                    )
                }
            }
        }
    }


    internal inner class AwaitingNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED -> {
                    val identity =
                        userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY)
                    if (identity !is Identity) {
                        return
                    }
                    awaitingServerSessionOperationsLock.lock()
                    val messageUid = awaitingServerSessionOperations[identity]
                    if (messageUid != null) {
                        awaitingServerSessionOperations.remove(identity)
                        queueNewDownloadMessagesExtendedPayloadOperation(identity, messageUid)
                    }
                    awaitingServerSessionOperationsLock.unlock()
                }

                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS -> {
                    val active =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_ACTIVE_KEY) as? Boolean ?: return
                    val ownedIdentity =
                        userInfo[IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_OWNED_IDENTITY_KEY] as Identity?
                    if (!active) {
                        return
                    }

                    awaitingIdentityReactivationOperationsLock.lock()
                    val list = awaitingIdentityReactivationOperations[ownedIdentity]
                    if (list != null) {
                        awaitingIdentityReactivationOperations.remove(ownedIdentity)
                        for (messageUid in list) {
                            queueNewDownloadMessagesExtendedPayloadOperation(
                                ownedIdentity!!,
                                messageUid
                            )
                        }
                    }
                    awaitingIdentityReactivationOperationsLock.unlock()
                }

            }
        }
    }
}
