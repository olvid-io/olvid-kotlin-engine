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
package io.olvid.engine.networksend.coordinators

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUidAndNumber
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.datatypes.RefreshOutboxAttachmentSignedUrlDelegate
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import io.olvid.engine.networksend.operations.RefreshOutboxAttachmentSignedUrlOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class RefreshOutboxAttachmentSignedUrlCoordinator(
    sendManagerSessionFactory: SendManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?
) : OnFinishCallback, OnCancelCallback, RefreshOutboxAttachmentSignedUrlDelegate {
    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>
    private val refreshOutboxAttachmentSignedUrlOperationQueue: NoDuplicateOperationQueue

    private val sendManagerSessionFactory: SendManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<IdentityAndUidAndNumber>?>
    private val awaitingIdentityReactivationOperationsLock: Lock

    private val lastUrlRefreshTimestamps: HashMap<IdentityAndUidAndNumber?, Long?>

    private val notificationListener: NotificationListener


    init {
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.lastUrlRefreshTimestamps = HashMap<IdentityAndUidAndNumber?, Long?>()

        refreshOutboxAttachmentSignedUrlOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>()

        awaitingIdentityReactivationOperations =
            HashMap<Identity?, MutableList<IdentityAndUidAndNumber>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()

        notificationListener = NotificationListener()
    }

    fun startProcessing() {
        refreshOutboxAttachmentSignedUrlOperationQueue.execute(
            1,
            "Engine-RefreshOutboxAttachmentSignedUrlCoordinator"
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        // register to NotificationCenter for NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS
        notificationListeningDelegate.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            notificationListener
        )
    }

    private fun queueNewRefreshOutboxAttachmentSignedUrlOperation(
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
        val op = RefreshOutboxAttachmentSignedUrlOperation(
            sendManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            messageUid,
            attachmentNumber,
            this,
            this
        )
        refreshOutboxAttachmentSignedUrlOperationQueue.queue(op)
    }

    private fun scheduleNewRefreshOutboxAttachmentSignedUrlOperationQueueing(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int
    ) {
        scheduler.schedule(
            IdentityAndUidAndNumber(ownedIdentity, messageUid, attachmentNumber),
            Runnable {
                queueNewRefreshOutboxAttachmentSignedUrlOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            },
            "RefreshOutboxAttachmentSignedUrlOperation"
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
            (operation as RefreshOutboxAttachmentSignedUrlOperation).ownedIdentity
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
        userInfo[UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED_OWNED_IDENTITY_KEY] = ownedIdentity
        userInfo[UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED_MESSAGE_UID_KEY] = messageUid
        userInfo[UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED_ATTACHMENT_NUMBER_KEY] = attachmentNumber
        notificationPostingDelegate?.postNotification(
            UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED,
            userInfo
        )
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity =
            (operation as RefreshOutboxAttachmentSignedUrlOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber

        var rfc = operation.reasonForCancel
        Logger.i("RefreshOutboxAttachmentSignedUrlOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            RefreshOutboxAttachmentSignedUrlOperation.RFC_ATTACHMENT_NOT_FOUND -> {}
            RefreshOutboxAttachmentSignedUrlOperation.RFC_IDENTITY_IS_INACTIVE -> waitForIdentityReactivation(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )

            RefreshOutboxAttachmentSignedUrlOperation.RFC_INVALID_NONCE, RefreshOutboxAttachmentSignedUrlOperation.RFC_DELETED_FROM_SERVER -> {
                try {
                    sendManagerSessionFactory.session.use { sendManagerSession ->
                        sendManagerSession.session.startTransaction()
                        val attachment: OutboxAttachment? = OutboxAttachment.get(
                            sendManagerSession,
                            ownedIdentity,
                            messageUid,
                            attachmentNumber
                        )
                        if (attachment != null) {
                            // Attachment no longer exists on the server. No point in continuing the upload, so simply mark the attachment as completely uploaded
                            attachment.setAcknowledgedChunkCount(attachment.numberOfChunks)
                        }
                        sendManagerSession.session.commit()
                    }
                } catch (e: SQLException) {
                    Logger.x(e)
                }
            }

            else -> scheduleNewRefreshOutboxAttachmentSignedUrlOperationQueueing(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        }
    }


    override fun refreshOutboxAttachmentSignedUrl(
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
                        queueNewRefreshOutboxAttachmentSignedUrlOperation(
                            ownedIdentity,
                            messageUid,
                            attachmentNumber
                        )
                    },
                    "too frequent RefreshOutboxAttachmentSignedUrlOperation",
                    delay
                )
            } else {
                queueNewRefreshOutboxAttachmentSignedUrlOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            }
        }
    }

    internal inner class NotificationListener : io.olvid.engine.datatypes.NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            if (IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS == notificationName) {
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
                        queueNewRefreshOutboxAttachmentSignedUrlOperation(
                            params.ownedIdentity,
                            params.uid,
                            params.attachmentNumber
                        )
                    }
                }
                awaitingIdentityReactivationOperationsLock.unlock()
            }
        }
    }
}
