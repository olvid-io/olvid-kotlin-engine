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
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUidAndNumber
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxAttachment.OutboxAttachmentCancelRequestedListener
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import io.olvid.engine.networksend.operations.CancelAttachmentUploadCompositeOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class CancelAttachmentUploadCoordinator(
    sendManagerSessionFactory: SendManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?
) : OutboxAttachmentCancelRequestedListener, OnCancelCallback, OnFinishCallback {
    private val sendManagerSessionFactory: SendManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?

    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    private val cancelAttachmentUploadOperationQueue: NoDuplicateOperationQueue
    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<IdentityAndUidAndNumber>?>
    private val awaitingIdentityReactivationOperationsLock: Lock

    private val notificationListener: NotificationListener


    init {
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride

        cancelAttachmentUploadOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>()

        awaitingIdentityReactivationOperations =
            HashMap<Identity?, MutableList<IdentityAndUidAndNumber>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()

        notificationListener = NotificationListener()
    }

    fun startProcessing() {
        cancelAttachmentUploadOperationQueue.execute(1, "Engine-CancelAttachmentUploadCoordinator")
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            notificationListener
        )
    }

    fun initialQueueing() {
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                val outboxAttachments: Array<OutboxAttachment?> =
                    OutboxAttachment.getAllToCancel(sendManagerSession)
                for (attachment in outboxAttachments) {
                    if (attachment == null) continue
                    queueNewCancelAttachmentUploadCompositeOperation(
                        attachment.getOwnedIdentity(),
                        attachment.messageUid,
                        attachment.attachmentNumber
                    )
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    private fun queueNewCancelAttachmentUploadCompositeOperation(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        Logger.d("Queueing new CancelAttachmentUploadCompositeOperation " + messageUid + "-" + attachmentNumber)
        val op = CancelAttachmentUploadCompositeOperation(
            sendManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity ?: return,
            messageUid ?: return,
            attachmentNumber,
            this,
            this
        )
        cancelAttachmentUploadOperationQueue.queue(op)
    }

    private fun scheduleNewCancelAttachmentUploadCompositeOperationQueueing(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int
    ) {
        scheduler.schedule(
            IdentityAndUidAndNumber(ownedIdentity, messageUid, attachmentNumber),
            Runnable {
                queueNewCancelAttachmentUploadCompositeOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            },
            "CancelAttachmentUploadCompositeOperation"
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


    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity =
            (operation as CancelAttachmentUploadCompositeOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber
        var rfc = operation.reasonForCancel
        Logger.w("CancelAttachmentUploadCompositeOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            CancelAttachmentUploadCompositeOperation.RFC_ATTACHMENT_NOT_FOUND_IN_DATABASE -> {}
            CancelAttachmentUploadCompositeOperation.RFC_IDENTITY_IS_INACTIVE -> waitForIdentityReactivation(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )

            else -> scheduleNewCancelAttachmentUploadCompositeOperationQueueing(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        }
    }

    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity =
            (operation as CancelAttachmentUploadCompositeOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber

        scheduler.clearFailedCount(
            IdentityAndUidAndNumber(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        )
    }

    // Notification received from OutboxAttachment database
    override fun outboxAttachmentCancelRequested(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        queueNewCancelAttachmentUploadCompositeOperation(
            ownedIdentity,
            messageUid,
            attachmentNumber
        )
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
                        queueNewCancelAttachmentUploadCompositeOperation(
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
