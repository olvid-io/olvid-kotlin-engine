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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUidAndNumber
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.databases.InboxAttachment
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.RefreshInboxAttachmentSignedUrlDelegate
import io.olvid.engine.networkfetch.operations.RefreshInboxAttachmentSignedUrlOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class RefreshInboxAttachmentSignedUrlCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?
) : OnFinishCallback, OnCancelCallback, RefreshInboxAttachmentSignedUrlDelegate {
    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>
    private val refreshInboxAttachmentSignedUrlOperationQueue: NoDuplicateOperationQueue

    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<IdentityAndUidAndNumber>?>
    private val awaitingIdentityReactivationOperationsLock: Lock
    private val awaitingIdentityReactivationNotificationListener: AwaitingIdentityReactivationNotificationListener

    private val lastUrlRefreshTimestamps: HashMap<IdentityAndUidAndNumber?, Long?>

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.lastUrlRefreshTimestamps = HashMap<IdentityAndUidAndNumber?, Long?>()

        refreshInboxAttachmentSignedUrlOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>()

        awaitingIdentityReactivationOperations =
            HashMap<Identity?, MutableList<IdentityAndUidAndNumber>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()
        awaitingIdentityReactivationNotificationListener =
            AwaitingIdentityReactivationNotificationListener()
    }

    fun startProcessing() {
        refreshInboxAttachmentSignedUrlOperationQueue.execute(
            1,
            "Engine-RefreshInboxAttachmentSignedUrlCoordinator"
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        // register to NotificationCenter for NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            awaitingIdentityReactivationNotificationListener
        )
    }

    private fun queueNewRefreshInboxAttachmentSignedUrlOperation(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int
    ) {
        synchronized(lastUrlRefreshTimestamps) {
            lastUrlRefreshTimestamps.put(
                IdentityAndUidAndNumber(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                ), System.currentTimeMillis()
            )
        }
        val op = RefreshInboxAttachmentSignedUrlOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            messageUid,
            attachmentNumber,
            this,
            this
        )
        refreshInboxAttachmentSignedUrlOperationQueue.queue(op)
    }

    private fun scheduleNewRefreshInboxAttachmentSignedUrlOperationQueueing(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int
    ) {
        scheduler.schedule(
            IdentityAndUidAndNumber(ownedIdentity, messageUid, attachmentNumber),
            Runnable {
                queueNewRefreshInboxAttachmentSignedUrlOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            },
            "RefreshInboxAttachmentSignedUrlOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }


    private fun waitForIdentityReactivation(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int
    ) {
        awaitingIdentityReactivationOperationsLock.lock()
        var list = awaitingIdentityReactivationOperations.get(ownedIdentity)
        if (list == null) {
            list = ArrayList<IdentityAndUidAndNumber>()
            awaitingIdentityReactivationOperations.put(ownedIdentity, list)
        }
        list.add(IdentityAndUidAndNumber(ownedIdentity, messageUid, attachmentNumber))
        awaitingIdentityReactivationOperationsLock.unlock()
    }

    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity =
            (operation as RefreshInboxAttachmentSignedUrlOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber
        scheduler.clearFailedCount(
            IdentityAndUidAndNumber(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        )

        val userInfo = HashMap<String, Any>()
        userInfo[DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_OWNED_IDENTITY_KEY] = ownedIdentity
        userInfo[DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_MESSAGE_UID_KEY] = messageUid
        userInfo[DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_ATTACHMENT_NUMBER_KEY] = attachmentNumber
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED,
            userInfo
        )
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity =
            (operation as RefreshInboxAttachmentSignedUrlOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber

        var rfc = operation.reasonForCancel
        Logger.i("RefreshInboxAttachmentSignedUrlOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            RefreshInboxAttachmentSignedUrlOperation.RFC_ATTACHMENT_NOT_FOUND -> {}
            RefreshInboxAttachmentSignedUrlOperation.RFC_IDENTITY_IS_INACTIVE -> waitForIdentityReactivation(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )

            RefreshInboxAttachmentSignedUrlOperation.RFC_DELETED_FROM_SERVER,
            RefreshInboxAttachmentSignedUrlOperation.RFC_UPLOAD_CANCELLED -> {
                try {
                    fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                        val attachment: InboxAttachment? = InboxAttachment.get(
                            fetchManagerSession,
                            ownedIdentity,
                            messageUid,
                            attachmentNumber
                        )
                        if (attachment != null) {
                            fetchManagerSession.session.startTransaction()
                            attachment.markForDeletion()
                            if (attachment.message?.canBeDeleted() == true) {
                                fetchManagerSession.markAsListedAndDeleteOnServerListener!!.messageCanBeDeletedFromServer(
                                    ownedIdentity,
                                    messageUid
                                )
                            }
                            fetchManagerSession.session.commit()
                        }
                    }
                } catch (e: SQLException) {
                    Logger.x(e)
                }
                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_MESSAGE_UID_KEY] = messageUid
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_ATTACHMENT_NUMBER_KEY] = attachmentNumber
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED,
                    userInfo
                )
            }

            else -> scheduleNewRefreshInboxAttachmentSignedUrlOperationQueueing(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        }
    }


    override fun refreshInboxAttachmentSignedUrl(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        if (ownedIdentity == null || messageUid == null) return
        synchronized(lastUrlRefreshTimestamps) {
            val timestamp = lastUrlRefreshTimestamps.get(
                IdentityAndUidAndNumber(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            )
            if (timestamp != null && System.currentTimeMillis() - timestamp < Constants.MINIMUM_URL_REFRESH_INTERVAL) {
                val delay =
                    Constants.MINIMUM_URL_REFRESH_INTERVAL - (System.currentTimeMillis() - timestamp)
                scheduler.schedule(
                    IdentityAndUidAndNumber(
                        ownedIdentity,
                        messageUid,
                        attachmentNumber
                    ),
                    Runnable {
                        queueNewRefreshInboxAttachmentSignedUrlOperation(
                            ownedIdentity,
                            messageUid,
                            attachmentNumber
                        )
                    },
                    "too frequent RefreshInboxAttachmentSignedUrlOperation",
                    delay
                )
            } else {
                queueNewRefreshInboxAttachmentSignedUrlOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            }
        }
    }

    internal inner class AwaitingIdentityReactivationNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            if (notificationName == IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS) {
                try {
                    val active =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_ACTIVE_KEY) as? Boolean ?: return
                    val ownedIdentity =
                        userInfo[IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_OWNED_IDENTITY_KEY] as Identity?
                    if (!active) {
                        return
                    }

                    awaitingIdentityReactivationOperationsLock.lock()
                    val list = awaitingIdentityReactivationOperations.get(ownedIdentity)
                    if (list != null) {
                        awaitingIdentityReactivationOperations.remove(ownedIdentity)
                        for (params in list) {
                            queueNewRefreshInboxAttachmentSignedUrlOperation(
                                params.ownedIdentity,
                                params.uid,
                                params.attachmentNumber
                            )
                        }
                    }
                    awaitingIdentityReactivationOperationsLock.unlock()
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }
    }
}
