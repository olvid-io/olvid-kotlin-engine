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
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.PriorityOperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUidAndNumber
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.databases.InboxAttachment
import io.olvid.engine.networkfetch.databases.InboxAttachment.InboxAttachmentListener
import io.olvid.engine.networkfetch.datatypes.DownloadAttachmentPriorityCategory
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.RefreshInboxAttachmentSignedUrlDelegate
import io.olvid.engine.networkfetch.operations.DownloadAttachmentOperation
import java.sql.SQLException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class DownloadAttachmentCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    refreshInboxAttachmentSignedUrlDelegate: RefreshInboxAttachmentSignedUrlDelegate
) : InboxAttachmentListener, OnCancelCallback {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val refreshInboxAttachmentSignedUrlDelegate: RefreshInboxAttachmentSignedUrlDelegate

    private var notificationListeningDelegate: NotificationListeningDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>
    private val downloadAttachmentOperationWeightQueue: PriorityOperationQueue // intended for download of small attachments
    private val downloadAttachmentOperationTimestampQueue: PriorityOperationQueue // intended for download of large attachments

    private val notificationListener: NotificationListener

    private val awaitingRefreshedUrlsOperations: HashMap<IdentityAndUidAndNumber?, AttachmentPriorityInfo?>
    private val awaitingRefreshedUrlsLock: Lock

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<AttachmentPriorityInfo>?>
    private val awaitingIdentityReactivationOperationsLock: Lock


    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.refreshInboxAttachmentSignedUrlDelegate = refreshInboxAttachmentSignedUrlDelegate

        downloadAttachmentOperationWeightQueue = PriorityOperationQueue()

        downloadAttachmentOperationTimestampQueue = PriorityOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUidAndNumber?>()

        notificationListener = NotificationListener()
        awaitingRefreshedUrlsOperations =
            HashMap<IdentityAndUidAndNumber?, AttachmentPriorityInfo?>()
        awaitingRefreshedUrlsLock = ReentrantLock()

        awaitingIdentityReactivationOperations =
            HashMap<Identity?, MutableList<AttachmentPriorityInfo>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()
    }

    fun startProcessing() {
        downloadAttachmentOperationWeightQueue.execute(
            4,
            "Engine-DownloadAttachmentCoordinator-weight"
        )
        downloadAttachmentOperationTimestampQueue.execute(
            4,
            "Engine-DownloadAttachmentCoordinator-timestamp"
        )
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED,
            notificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            notificationListener
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                val attachmentsToResume: Array<InboxAttachment> =
                    InboxAttachment.getAllAttachmentsToResume(fetchManagerSession)
                for (inboxAttachment in attachmentsToResume) {
                    queueNewDownloadAttachmentOperation(
                        inboxAttachment.getOwnedIdentity(),
                        inboxAttachment.messageUid,
                        inboxAttachment.attachmentNumber,
                        inboxAttachment.priorityCategory!!,
                        inboxAttachment.priority
                    )
                    // post an initial progress value so the app directly has a progress to show, even if download does not progress
                    fetchManagerSession.inboxAttachmentListener!!.attachmentDownloadProgressed(
                        inboxAttachment.getOwnedIdentity(),
                        inboxAttachment.messageUid,
                        inboxAttachment.attachmentNumber,
                        inboxAttachment.progress
                    )
                }

                val attachmentsNotToResume: Array<InboxAttachment> =
                    InboxAttachment.getAllPartialAttachmentsNotToResume(
                        fetchManagerSession
                    )
                for (inboxAttachment in attachmentsNotToResume) {
                    // also post a progress value for attachments that won't be downloaded
                    fetchManagerSession.inboxAttachmentListener!!.attachmentDownloadProgressed(
                        inboxAttachment.getOwnedIdentity(),
                        inboxAttachment.messageUid,
                        inboxAttachment.attachmentNumber,
                        inboxAttachment.progress
                    )
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    private fun queueNewDownloadAttachmentOperation(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        priorityCategory: Int,
        initialPriority: Long
    ) {
        Logger.d("Download attachment coordinator queueing new DownloadAttachmentOperation.")
        val op = DownloadAttachmentOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity!!,
            messageUid!!,
            attachmentNumber,
            priorityCategory,
            initialPriority,
            this,
            null,
            this
        )
        when (priorityCategory) {
            DownloadAttachmentPriorityCategory.WEIGHT -> {
                downloadAttachmentOperationWeightQueue.queue(op)
                val lowestPriorityExecutingOperation =
                    downloadAttachmentOperationWeightQueue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority()
                if (lowestPriorityExecutingOperation != null && lowestPriorityExecutingOperation.getPriority() > initialPriority) {
                    Logger.d("Canceling a DownloadAttachmentOperation with lower priority " + lowestPriorityExecutingOperation.getPriority())
                    lowestPriorityExecutingOperation.cancel(DownloadAttachmentOperation.RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY)
                }
            }

            DownloadAttachmentPriorityCategory.TIMESTAMP -> {
                downloadAttachmentOperationTimestampQueue.queue(op)
                val lowestPriorityExecutingOperation =
                    downloadAttachmentOperationTimestampQueue.getExecutingOperationThatShouldBeCancelledWhenQueueingWithHigherPriority()
                if (lowestPriorityExecutingOperation != null && lowestPriorityExecutingOperation.getPriority() > initialPriority) {
                    Logger.d("Canceling a DownloadAttachmentOperation with lower priority " + lowestPriorityExecutingOperation.getPriority())
                    lowestPriorityExecutingOperation.cancel(DownloadAttachmentOperation.RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY)
                }
            }

            else -> Logger.w("Trying to queue a DownloadAttachmentOperation with unknown priorityCategory " + priorityCategory)
        }
    }

    private fun scheduleNewDownloadAttachmentOperationQueueing(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int,
        priorityCategory: Int,
        initialPriority: Long
    ) {
        scheduler.schedule(
            IdentityAndUidAndNumber(ownedIdentity, messageUid, attachmentNumber),
            Runnable {
                queueNewDownloadAttachmentOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    priorityCategory,
                    initialPriority
                )
            },
            "DownloadAttachmentOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    private fun waitForRefreshedUrls(
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int,
        priorityCategory: Int,
        initialPriority: Long
    ) {
        awaitingRefreshedUrlsLock.lock()
        awaitingRefreshedUrlsOperations.put(
            IdentityAndUidAndNumber(
                ownedIdentity,
                messageUid,
                attachmentNumber
            ),
            AttachmentPriorityInfo(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                priorityCategory,
                initialPriority
            )
        )
        awaitingRefreshedUrlsLock.unlock()
    }

    private fun waitForIdentityReactivation(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        priorityCategory: Int,
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
                priorityCategory,
                initialPriority
            )
        )
        awaitingIdentityReactivationOperationsLock.unlock()
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

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity = (operation as DownloadAttachmentOperation).ownedIdentity
        val messageUid = operation.messageUid
        val attachmentNumber = operation.attachmentNumber
        val priorityCategory = operation.priorityCategory
        val initialPriority = operation.getPriority()
        var rfc = operation.reasonForCancel
        Logger.i("DownloadAttachmentOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            DownloadAttachmentOperation.RFC_DECRYPTION_ERROR, DownloadAttachmentOperation.RFC_INVALID_CHUNK, DownloadAttachmentOperation.RFC_ATTACHMENT_CANNOT_BE_FETCHED, DownloadAttachmentOperation.RFC_UNABLE_TO_WRITE_CHUNK_TO_FILE, DownloadAttachmentOperation.RFC_UPLOAD_CANCELLED_BY_SENDER -> {
                // We do not try to download the attachment again and mark it for deletion. We notify that the downloadAttachment failed.
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

            DownloadAttachmentOperation.RFC_ATTACHMENT_CANNOT_BE_FOUND, DownloadAttachmentOperation.RFC_FETCH_NOT_REQUESTED, DownloadAttachmentOperation.RFC_MARKED_FOR_DELETION -> {}
            DownloadAttachmentOperation.RFC_IDENTITY_IS_INACTIVE ->                 // wait for identity to become active again
                waitForIdentityReactivation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    priorityCategory,
                    initialPriority
                )

            DownloadAttachmentOperation.RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY -> {
                queueNewDownloadAttachmentOperation(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    priorityCategory,
                    initialPriority
                )

                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_MESSAGE_UID_KEY] = messageUid
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_ATTACHMENT_NUMBER] = attachmentNumber
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED,
                    userInfo
                )
            }

            DownloadAttachmentOperation.RFC_NOT_FOUND_ON_SERVER, DownloadAttachmentOperation.RFC_INVALID_SIGNED_URL -> {
                waitForRefreshedUrls(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    priorityCategory,
                    initialPriority
                )
                refreshInboxAttachmentSignedUrlDelegate.refreshInboxAttachmentSignedUrl(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            }

            DownloadAttachmentOperation.RFC_DOWNLOAD_PAUSED -> {
                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_MESSAGE_UID_KEY] = messageUid
                userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_ATTACHMENT_NUMBER] = attachmentNumber
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED,
                    userInfo
                )
            }

            DownloadAttachmentOperation.RFC_NETWORK_ERROR -> scheduleNewDownloadAttachmentOperationQueueing(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                priorityCategory,
                initialPriority
            )

            else -> scheduleNewDownloadAttachmentOperationQueueing(
                ownedIdentity,
                messageUid,
                attachmentNumber,
                priorityCategory,
                initialPriority
            )
        }
    }

    internal inner class NotificationListener : io.olvid.engine.datatypes.NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED -> {
                    val ownedIdentity =
                        userInfo?.get(DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_OWNED_IDENTITY_KEY) as Identity?
                    val messageUid =
                        userInfo?.get(DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_MESSAGE_UID_KEY) as UID?
                    val attachmentNumber =
                        userInfo?.get(DownloadNotifications.NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_ATTACHMENT_NUMBER_KEY) as Int? ?: return
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
                        queueNewDownloadAttachmentOperation(
                            ownedIdentity, messageUid, attachmentNumber,
                            attachmentPriorityInfo.priorityCategory,
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
                            queueNewDownloadAttachmentOperation(
                                params.ownedIdentity,
                                params.messageUid,
                                params.attachmentNumber,
                                params.priorityCategory,
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
        priorityCategory: Int,
        initialPriority: Long
    ) {
        @JvmField val ownedIdentity: Identity?
        @JvmField val messageUid: UID?
        @JvmField val attachmentNumber: Int
        @JvmField val priorityCategory: Int
        @JvmField val initialPriority: Long

        init {
            this.ownedIdentity = ownedIdentity
            this.messageUid = messageUid
            this.attachmentNumber = attachmentNumber
            this.priorityCategory = priorityCategory
            this.initialPriority = initialPriority
        }
    }

    override fun attachmentDownloadProgressed(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        progress: Float
    ) {
        val userInfo = HashMap<String, Any>()
        ownedIdentity?.let { userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_OWNED_IDENTITY_KEY] = it }
        messageUid?.let { userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_UID_KEY] = it }
        userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY] = attachmentNumber
        userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY] = progress
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS,
            userInfo
        )
    }

    override fun attachmentDownloadFinished(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        // Warning, this method is also called by the manager when resendAllDownloadedAttachmentNotifications is called
        val userInfo = HashMap<String, Any>()
        ownedIdentity?.let { userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_OWNED_IDENTITY_KEY] = it }
        messageUid?.let { userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_MESSAGE_UID_KEY] = it }
        userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_ATTACHMENT_NUMBER_KEY] = attachmentNumber
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED,
            userInfo
        )
    }

    override fun attachmentDownloadWasRequested(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        priorityCategory: Int,
        initialPriority: Long
    ) {
        queueNewDownloadAttachmentOperation(
            ownedIdentity,
            messageUid,
            attachmentNumber,
            priorityCategory,
            initialPriority
        )
    }
}
