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
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.PriorityOperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUidAndNumber
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxAttachment.OutboxAttachmentCanBeSentListener
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.RefreshOutboxAttachmentSignedUrlDelegate
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import io.olvid.engine.networksend.operations.UploadAttachmentCompositeOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class SendAttachmentCoordinator(
    sendManagerSessionFactory: SendManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    refreshOutboxAttachmentSignedUrlCoordinator: RefreshOutboxAttachmentSignedUrlCoordinator
) : OutboxAttachmentCanBeSentListener, OnCancelCallback {
    private val sendManagerSessionFactory: SendManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val refreshOutboxAttachmentSignedUrlDelegate: RefreshOutboxAttachmentSignedUrlDelegate

    private val sendAttachmentOperationQueue: PriorityOperationQueue
    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>

    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    private val fileFailedAttemptCounts: HashMap<IdentityAndUidAndNumber?, Int?>

    private val notificationListener: NotificationListener
    private val awaitingRefreshedUrlsOperations: HashMap<IdentityAndUidAndNumber?, AttachmentPriorityInfo?>
    private val awaitingRefreshedUrlsLock: Lock

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<AttachmentPriorityInfo>?>
    private val awaitingIdentityReactivationOperationsLock: Lock


    init {
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.refreshOutboxAttachmentSignedUrlDelegate = refreshOutboxAttachmentSignedUrlCoordinator

        sendAttachmentOperationQueue = PriorityOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>()

        fileFailedAttemptCounts = HashMap<IdentityAndUidAndNumber?, Int?>()

        notificationListener = NotificationListener()
        awaitingRefreshedUrlsOperations =
            HashMap<IdentityAndUidAndNumber?, AttachmentPriorityInfo?>()
        awaitingRefreshedUrlsLock = ReentrantLock()

        awaitingIdentityReactivationOperations =
            HashMap<Identity?, MutableList<AttachmentPriorityInfo>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()
    }

    fun startProcessing() {
        sendAttachmentOperationQueue.execute(4, "Engine-SendAttachmentCoordinator")
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        this.notificationListeningDelegate!!.addListener(
            UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED,
            notificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            notificationListener
        )
    }

    fun initialQueueing() {
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                val messages: Array<OutboxMessage?> =
                    OutboxMessage.getAll(sendManagerSession)
                for (message in messages) {
                    if (message == null) continue
                    if (message.uidFromServer != null) {
                        for (attachment in message.attachments!!) {
                            if (attachment == null) continue
                            if (!attachment.isAcknowledged) {
                                queueNewSendAttachmentCompositeOperation(
                                    attachment.getOwnedIdentity(),
                                    attachment.messageUid,
                                    attachment.attachmentNumber,
                                    attachment.priority
                                )
                            }
                        }
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    private fun queueNewSendAttachmentCompositeOperation(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        initialPriority: Long
    ) {
        Logger.d("Queueing new UploadAttachmentCompositeOperation " + messageUid + "-" + attachmentNumber + " with priority " + initialPriority)
        val op = UploadAttachmentCompositeOperation(
            sendManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity ?: return,
            messageUid ?: return,
            attachmentNumber,
            initialPriority,
            this,
            null,
            this
        )
        sendAttachmentOperationQueue.queue(op)
        val lowestPriorityExecutingOperation =
            sendAttachmentOperationQueue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority()
        if (lowestPriorityExecutingOperation != null && lowestPriorityExecutingOperation.getPriority() > initialPriority) {
            Logger.d("Canceling a UploadAttachmentCompositeOperation with lower priority " + lowestPriorityExecutingOperation.getPriority())
            lowestPriorityExecutingOperation.cancel(UploadAttachmentCompositeOperation.RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY)
        }
    }

    private fun scheduleNewSendAttachmentCompositeOperationQueueing(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int,
        initialPriority: Long
    ) {
        scheduler.schedule(
            IdentityAndUidAndNumber(ownedIdentity, messageUid, attachmentNumber),
            Runnable {
                queueNewSendAttachmentCompositeOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    initialPriority
                )
            },
            "UploadAttachmentCompositeOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    private fun waitForRefreshedUrls(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int,
        initialPriority: Long
    ) {
        awaitingRefreshedUrlsLock.lock()
        awaitingRefreshedUrlsOperations.put(
            IdentityAndUidAndNumber(
                ownedIdentity,
                messageUid,
                attachmentNumber
            ), AttachmentPriorityInfo(ownedIdentity, messageUid, attachmentNumber, initialPriority)
        )
        awaitingRefreshedUrlsLock.unlock()
    }

    fun resetFailedAttemptCount(ownedIdentity: Identity, messageUid: UID, attachmentNumber: Int) {
        scheduler.clearFailedCount(
            IdentityAndUidAndNumber(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        )
    }

    private fun waitForIdentityReactivation(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        initialPriority: Long
    ) {
        awaitingIdentityReactivationOperationsLock.lock()
        var list = awaitingIdentityReactivationOperations.get(ownedIdentity)
        if (list == null) {
            list = ArrayList<AttachmentPriorityInfo>()
            awaitingIdentityReactivationOperations.put(ownedIdentity, list)
        }
        list.add(
            AttachmentPriorityInfo(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                initialPriority
            )
        )
        awaitingIdentityReactivationOperationsLock.unlock()
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity = (operation as UploadAttachmentCompositeOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber
        val priority = operation.getPriority()
        var rfc = operation.reasonForCancel
        Logger.w("UploadAttachmentCompositeOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            UploadAttachmentCompositeOperation.RFC_ATTACHMENT_FILE_NOT_READABLE -> {
                // count the number of failed attempts, cancel the attachment after 8 fails
                var failedCount = fileFailedAttemptCounts.get(
                    IdentityAndUidAndNumber(
                        ownedIdentity,
                        messageUid,
                        attachmentNumber
                    )
                )
                if (failedCount == null) {
                    failedCount = 0
                }
                fileFailedAttemptCounts.put(
                    IdentityAndUidAndNumber(
                        ownedIdentity,
                        messageUid,
                        attachmentNumber
                    ), failedCount + 1
                )

                if (failedCount >= 8) {
                    // failed 8 times, mark the attachment for deletion
                    try {
                        sendManagerSessionFactory.session.use { sendManagerSession ->
                            val outboxAttachment: OutboxAttachment? =
                                OutboxAttachment.get(
                                    sendManagerSession,
                                    ownedIdentity,
                                    messageUid,
                                    attachmentNumber
                                )
                            if (outboxAttachment != null) {
                                outboxAttachment.setCancelExternallyRequested()
                                return@use
                            }
                        }
                    } catch (_: SQLException) {
                    }
                }
                scheduleNewSendAttachmentCompositeOperationQueueing(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    priority
                )
            }

            UploadAttachmentCompositeOperation.RFC_INVALID_SIGNED_URL -> {
                waitForRefreshedUrls(ownedIdentity, messageUid, attachmentNumber, priority)
                refreshOutboxAttachmentSignedUrlDelegate.refreshOutboxAttachmentSignedUrl(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            }

            UploadAttachmentCompositeOperation.RFC_ATTACHMENT_NOT_FOUND_IN_DATABASE, UploadAttachmentCompositeOperation.RFC_MESSAGE_HAS_NO_UID_FROM_SERVER -> {}
            UploadAttachmentCompositeOperation.RFC_IDENTITY_IS_INACTIVE -> waitForIdentityReactivation(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                priority
            )

            UploadAttachmentCompositeOperation.RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY -> queueNewSendAttachmentCompositeOperation(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                priority
            )

            else -> scheduleNewSendAttachmentCompositeOperationQueueing(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                priority
            )
        }
    }

    // Notification received from OutboxAttachment database
    override fun outboxAttachmentCanBeSent(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        initialPriority: Long
    ) {
        queueNewSendAttachmentCompositeOperation(
            ownedIdentity,
            messageUid,
            attachmentNumber,
            initialPriority
        )
    }

    internal inner class NotificationListener : io.olvid.engine.datatypes.NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED -> {
                    val ownedIdentity =
                        userInfo?.get(UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED_OWNED_IDENTITY_KEY) as Identity?
                    val messageUid =
                        userInfo?.get(UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED_MESSAGE_UID_KEY) as UID?
                    val attachmentNumber =
                        userInfo?.get(UploadNotifications.NOTIFICATION_OUTBOX_ATTACHMENT_SIGNED_URL_REFRESHED_ATTACHMENT_NUMBER_KEY) as? Int ?: return

                    awaitingRefreshedUrlsLock.lock()
                    val attachmentPriorityInfo = awaitingRefreshedUrlsOperations.get(
                        IdentityAndUidAndNumber(
                            ownedIdentity!!,
                            messageUid!!,
                            attachmentNumber
                        )
                    )
                    if (attachmentPriorityInfo != null) {
                        awaitingRefreshedUrlsOperations.remove(
                            IdentityAndUidAndNumber(
                                ownedIdentity,
                                messageUid,
                                attachmentNumber
                            )
                        )
                        queueNewSendAttachmentCompositeOperation(
                            attachmentPriorityInfo.ownedIdentity,
                            attachmentPriorityInfo.messageUid,
                            attachmentPriorityInfo.attachmentNumber,
                            attachmentPriorityInfo.initialPriority
                        )
                    }
                    awaitingRefreshedUrlsLock.unlock()
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
                    val list = awaitingIdentityReactivationOperations.get(ownedIdentity)
                    if (list != null) {
                        awaitingIdentityReactivationOperations.remove(ownedIdentity)
                        for (params in list) {
                            queueNewSendAttachmentCompositeOperation(
                                params.ownedIdentity,
                                params.messageUid,
                                params.attachmentNumber,
                                params.initialPriority
                            )
                        }
                    }
                    awaitingIdentityReactivationOperationsLock.unlock()
                }
            }
        }
    }

    private class AttachmentPriorityInfo(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        initialPriority: Long
    ) {
        @JvmField val ownedIdentity: Identity?
        @JvmField val messageUid: UID?
        @JvmField val attachmentNumber: Int
        @JvmField val initialPriority: Long

        init {
            this.ownedIdentity = ownedIdentity
            this.messageUid = messageUid
            this.attachmentNumber = attachmentNumber
            this.initialPriority = initialPriority
        }
    }
}
