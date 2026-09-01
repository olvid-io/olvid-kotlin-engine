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
import io.olvid.engine.datatypes.NoDuplicatePriorityOperationQueue
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.ReceivedAttachment
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ProcessDownloadedMessageDelegate
import io.olvid.engine.networkfetch.databases.InboxAttachment
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.databases.InboxMessage.InboxMessageListener
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.DownloadMessagesAndListAttachmentsDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.RegisterServerPushNotificationDelegate
import io.olvid.engine.networkfetch.operations.DownloadMessagesAndListAttachmentsOperation
import io.olvid.engine.networkfetch.operations.ProcessPreKeyMessagesForNewContactOperation
import io.olvid.engine.networkfetch.operations.ProcessWebsocketReceivedMessageOperation
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class DownloadMessagesAndListAttachmentsCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate
) : OnCancelCallback, DownloadMessagesAndListAttachmentsDelegate, InboxMessageListener,
    OnFinishCallback, NotificationListener {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val createServerSessionDelegate: CreateServerSessionDelegate
    private var registerServerPushNotificationDelegate: RegisterServerPushNotificationDelegate? =
        null

    private val scheduler: ExponentialBackoffRepeatingScheduler<Identity?>
    private val downloadMessagesAndListAttachmentsOperationQueue: NoDuplicatePriorityOperationQueue

    private var processDownloadedMessageDelegate: ProcessDownloadedMessageDelegate? = null

    private val awaitingServerSessionOperations: HashMap<Identity?, UID?>
    private val awaitingServerSessionOperationsLock: Lock
    private val awaitingNotificationListener: AwaitingNotificationListener

    private var notificationListeningDelegate: NotificationListeningDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.createServerSessionDelegate = createServerSessionDelegate

        downloadMessagesAndListAttachmentsOperationQueue = NoDuplicatePriorityOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<Identity?>()
        awaitingServerSessionOperations = HashMap<Identity?, UID?>()
        awaitingServerSessionOperationsLock = ReentrantLock()

        awaitingNotificationListener = AwaitingNotificationListener()
    }

    fun startProcessing() {
        downloadMessagesAndListAttachmentsOperationQueue.execute(
            1,
            "Engine-DownloadMessagesAndListAttachmentsCoordinator"
        )
    }

    fun setRegisterServerPushNotificationDelegate(registerServerPushNotificationDelegate: RegisterServerPushNotificationDelegate?) {
        this.registerServerPushNotificationDelegate = registerServerPushNotificationDelegate
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            awaitingNotificationListener
        )
        this.notificationListeningDelegate!!.addListener(
            IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY,
            this
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setProcessDownloadedMessageDelegate(processDownloadedMessageDelegate: ProcessDownloadedMessageDelegate?) {
        this.processDownloadedMessageDelegate = processDownloadedMessageDelegate
    }

    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                // no longer download messages at startup, we download after a successful push notification registration
                // retry processing messages that were downloaded but never decrypted nor marked for deletion
                val unprocessedMessages: Array<InboxMessage> =
                    InboxMessage.getUnprocessedMessages(fetchManagerSession)
                for (inboxMessage in unprocessedMessages) {
                    messageWasDownloaded(inboxMessage.networkReceivedMessage)
                }

                // resend notifications for decrypted messages not yet marked for deletion
                val decryptedInboxMessages: Array<InboxMessage> =
                    InboxMessage.getDecryptedMessages(fetchManagerSession)
                for (inboxMessage in decryptedInboxMessages) {
                    messageDecrypted(inboxMessage, inboxMessage.attachments)
                }

                // check if any message marked for deletion can be deleted
                val markedForDeletionMessages: Array<InboxMessage> =
                    InboxMessage.getMarkedForDeletionMessages(fetchManagerSession)
                for (inboxMessage in markedForDeletionMessages) {
                    if (inboxMessage.canBeDeleted()) {
                        fetchManagerSession.markAsListedAndDeleteOnServerListener!!.messageCanBeDeletedFromServer(
                            inboxMessage.getOwnedIdentity(),
                            inboxMessage.uid
                        )
                    }
                }

                //delete pre key messages without contact that are more than 2 weeks old
                val expiredMessages: MutableList<InboxMessage> =
                    InboxMessage.getExpiredPendingPreKeyMessages(
                        fetchManagerSession,
                        System.currentTimeMillis() - Constants.PRE_KEY_INBOX_NO_CONTACT_DURATION
                    )
                if (!expiredMessages.isEmpty()) {
                    for (inboxMessage in expiredMessages) {
                        inboxMessage.markForDeletion()
                        for (inboxAttachment in inboxMessage.attachments ?: emptyArray()) {
                            inboxAttachment.markForDeletion()
                        }
                        fetchManagerSession.markAsListedAndDeleteOnServerListener!!.messageCanBeDeletedFromServer(
                            inboxMessage.getOwnedIdentity(),
                            inboxMessage.uid
                        )
                    }
                    fetchManagerSession.session.commit()
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    private fun queueNewDownloadMessagesAndListAttachmentsOperation(
        identity: Identity?,
        deviceUid: UID?
    ) {
        val op = DownloadMessagesAndListAttachmentsOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            identity ?: return,
            deviceUid ?: return,
            0,
            this,
            this
        )
        downloadMessagesAndListAttachmentsOperationQueue.queue(op)
    }

    private fun scheduleNewDownloadMessagesAndListAttachmentsOperationQueueing(
        identity: Identity?,
        deviceUid: UID?
    ) {
        scheduler.schedule(
            identity,
            Runnable { queueNewDownloadMessagesAndListAttachmentsOperation(identity, deviceUid) },
            "DownloadMessagesAndListAttachmentsOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    private fun waitForServerSession(identity: Identity?, deviceUid: UID?) {
        awaitingServerSessionOperationsLock.lock()
        awaitingServerSessionOperations.put(identity, deviceUid)
        awaitingServerSessionOperationsLock.unlock()
    }

    // region implement InboxMessageListener
    override fun messageWasDownloaded(networkReceivedMessage: NetworkReceivedMessage?) {
        if (processDownloadedMessageDelegate == null) {
            Logger.w("A message was downloaded but no ProcessDownloadedMessageDelegate is set yet.")
            return
        }
        this.processDownloadedMessageDelegate!!.processDownloadedMessage(networkReceivedMessage)
    }

    override fun messageDecrypted(inboxMessage: InboxMessage?, attachments: Array<InboxAttachment>?) {
        if (notificationPostingDelegate != null) {
            val userInfo = HashMap<String, Any>()
            inboxMessage?.decryptedApplicationMessage?.let { userInfo[DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED_MESSAGE_KEY] = it }
            val receivedAttachments = arrayOfNulls<ReceivedAttachment>(attachments?.size ?: 0)
            if (attachments != null) {
                for (i in attachments.indices) {
                    val att = attachments[i]
                    receivedAttachments[i] = ReceivedAttachment(
                        att.getOwnedIdentity(),
                        att.messageUid,
                        att.attachmentNumber,
                        att.metadata,
                        att.url,
                        att.plaintextExpectedLength,
                        att.plaintextReceivedLength,
                        att.isUploadCancelledBySender,
                        att.isDownloadRequested
                    )
                }
            }
            userInfo[DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED_ATTACHMENTS_KEY] = receivedAttachments
            notificationPostingDelegate?.postNotification(
                DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED,
                userInfo
            )
        }
    }

    // endregion
    internal inner class AwaitingNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            when (notificationName) {
                DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED -> {
                    val identityObject =
                        userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY)
                    if (identityObject !is Identity) {
                        return
                    }
                    val identity = identityObject
                    awaitingServerSessionOperationsLock.lock()
                    val deviceUid = awaitingServerSessionOperations.get(identity)
                    if (deviceUid != null) {
                        awaitingServerSessionOperations.remove(identity)
                        queueNewDownloadMessagesAndListAttachmentsOperation(identity, deviceUid)
                    }
                    awaitingServerSessionOperationsLock.unlock()
                }
            }
        }
    }

    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity =
            (operation as DownloadMessagesAndListAttachmentsOperation).ownedIdentity
        val deviceUid = operation.deviceUid
        val timestampOfLastMessageBeforeTruncation =
            operation.timestampOfLastMessageBeforeTruncation
        scheduler.clearFailedCount(ownedIdentity)

        if (timestampOfLastMessageBeforeTruncation != null) {
            // if listing was truncated --> trigger a new list in 10 seconds, once messages are processed and deleted from server
            downloadMessagesAndListAttachmentsOperationQueue.queue(
                DownloadMessagesAndListAttachmentsOperation(
                    fetchManagerSessionFactory,
                    sslSocketFactory,
                    userAgentOverride,
                    ownedIdentity,
                    deviceUid,
                    timestampOfLastMessageBeforeTruncation,
                    this,
                    this
                )
            )
        } else {
            fetchManagerSessionFactory.markOwnedIdentityAsUpToDate(ownedIdentity)
        }

        val userInfo = HashMap<String, Any>()
        userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLLED_OWNED_IDENTITY_KEY] = ownedIdentity
        userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLLED_SUCCESS_KEY] = true
        userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLLED_TRUNCATED_KEY] = (timestampOfLastMessageBeforeTruncation != null)
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_SERVER_POLLED,
            userInfo
        )
    }

    override fun onCancelCallback(operation: Operation) {
        if (operation is DownloadMessagesAndListAttachmentsOperation) {
            val identity = operation.ownedIdentity
            val deviceUid = operation.deviceUid
            var rfc = operation.reasonForCancel
            Logger.i("DownloadMessagesAndListAttachmentsOperation cancelled for reason " + rfc)
            if (rfc == null) {
                rfc = Operation.RFC_NULL
            }
            when (rfc) {
                DownloadMessagesAndListAttachmentsOperation.RFC_INVALID_SERVER_SESSION -> {
                    waitForServerSession(identity, deviceUid)
                    createServerSessionDelegate.createServerSession(identity)
                }

                DownloadMessagesAndListAttachmentsOperation.RFC_DEVICE_NOT_REGISTERED -> {
                    if (registerServerPushNotificationDelegate != null) {
                        registerServerPushNotificationDelegate!!.registerServerPushNotification(
                            identity,
                            false
                        )
                    } else {
                        Logger.e("Recieved a DEVICE_NOT_REGISTERED error from the server and registerServerPushNotificationDelegate was not initialized")
                    }
                }

                DownloadMessagesAndListAttachmentsOperation.RFC_IDENTITY_IS_INACTIVE -> {}
                else -> {
                    scheduleNewDownloadMessagesAndListAttachmentsOperationQueueing(
                        identity,
                        deviceUid
                    )

                    // notify polling failed
                    val userInfo = HashMap<String, Any>()
                    userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLLED_OWNED_IDENTITY_KEY] = identity
                    userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLLED_SUCCESS_KEY] = false
                    userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLLED_TRUNCATED_KEY] = false
                    notificationPostingDelegate?.postNotification(
                        DownloadNotifications.NOTIFICATION_SERVER_POLLED,
                        userInfo
                    )
                }
            }
        } else if (operation is ProcessWebsocketReceivedMessageOperation) {
            val identity = operation.ownedIdentity
            val deviceUid = operation.deviceUid
            Logger.i("ProcessWebsocketReceivedMessageOperation cancelled")

            // processing of websocket received message failed --> revert to download and list
            scheduleNewDownloadMessagesAndListAttachmentsOperationQueueing(identity, deviceUid)
        }
    }


    override fun downloadMessagesAndListAttachments(identity: Identity?, deviceUid: UID?) {
        queueNewDownloadMessagesAndListAttachmentsOperation(identity, deviceUid)
    }

    override fun processWebsocketDownloadedMessage(
        identity: Identity?,
        deviceUid: UID?,
        messagePayload: ByteArray?
    ) {
        if (identity == null || messagePayload == null) return
        val op = ProcessWebsocketReceivedMessageOperation(
            fetchManagerSessionFactory,
            identity,
            deviceUid,
            messagePayload,
            null,
            this
        )
        downloadMessagesAndListAttachmentsOperationQueue.queue(op)
    }


    override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
        if (IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY == notificationName) {
            try {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_OWNED_IDENTITY_KEY) as Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_CONTACT_IDENTITY_KEY) as Identity?
                val active =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_ACTIVE_KEY) as? Boolean ?: return

                if (active && ownedIdentity != null && contactIdentity != null) {
                    val op = ProcessPreKeyMessagesForNewContactOperation(
                        fetchManagerSessionFactory,
                        ownedIdentity,
                        contactIdentity,
                        null,
                        null
                    )
                    downloadMessagesAndListAttachmentsOperationQueue.queue(op)
                }
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
    }
}
