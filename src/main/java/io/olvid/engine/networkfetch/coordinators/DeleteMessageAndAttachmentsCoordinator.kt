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
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networkfetch.databases.InboxMessage.MarkAsListedAndDeleteOnServerListener
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.DeleteOrMarkAsListed
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.IdentityAndUidAndDeletedOrMarkAsListed
import io.olvid.engine.networkfetch.datatypes.MessageBatchProvider
import io.olvid.engine.networkfetch.datatypes.UidAndDeletedOrMarkAsListed
import io.olvid.engine.networkfetch.operations.DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation
import java.util.ArrayDeque
import java.util.Queue
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class DeleteMessageAndAttachmentsCoordinator(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val createServerSessionDelegate: CreateServerSessionDelegate
) : OnCancelCallback, MarkAsListedAndDeleteOnServerListener, MessageBatchProvider,
    OnFinishCallback {

    private val scheduler: ExponentialBackoffRepeatingScheduler<Identity> = ExponentialBackoffRepeatingScheduler()
    private val messageUidsToDeleteByOwnedIdentity: HashMap<Identity, Queue<UidAndDeletedOrMarkAsListed>?> = HashMap()
    private val deleteMessageAndAttachmentsFromServerOperationQueue: NoDuplicateOperationQueue = NoDuplicateOperationQueue()

    private val awaitingServerSessionOperations: HashMap<Identity, MutableList<IdentityAndUidAndDeletedOrMarkAsListed>?> = HashMap()
    private val awaitingServerSessionOperationsLock: Lock = ReentrantLock()
    private val serverSessionCreatedNotificationListener: ServerSessionCreatedNotificationListener


    init {
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        serverSessionCreatedNotificationListener = ServerSessionCreatedNotificationListener()
    }


    fun startProcessing() {
        deleteMessageAndAttachmentsFromServerOperationQueue.execute(
            1,
            "Engine-DeleteMessageAndAttachmentsCoordinator"
        )
    }


    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        notificationListeningDelegate.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            serverSessionCreatedNotificationListener
        )
    }


    private fun queueNewDeleteMessageAndAttachmentsFromServerOperation(
        ownedIdentity: Identity,
        messageUid: UID?,
        deleteOrMarkAsListed: DeleteOrMarkAsListed
    ) {
        if (messageUid != null) {
            synchronized(messageUidsToDeleteByOwnedIdentity) {
                var queue = messageUidsToDeleteByOwnedIdentity[ownedIdentity]
                if (queue == null) {
                    queue = ArrayDeque<UidAndDeletedOrMarkAsListed>()
                    messageUidsToDeleteByOwnedIdentity[ownedIdentity] = queue
                }
                queue.add(UidAndDeletedOrMarkAsListed(messageUid, deleteOrMarkAsListed))
            }
        }
        val op = DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            this,
            this,
            this
        )
        deleteMessageAndAttachmentsFromServerOperationQueue.queue(op)
    }

    override fun getBatchOFMessageUids(ownedIdentity: Identity?): Array<UidAndDeletedOrMarkAsListed> {
        val messageUidsAndMarkAsListed: MutableList<UidAndDeletedOrMarkAsListed> = ArrayList()
        synchronized(messageUidsToDeleteByOwnedIdentity) {
            val queue = messageUidsToDeleteByOwnedIdentity[ownedIdentity]
            if (!queue.isNullOrEmpty()) {
                do {
                    messageUidsAndMarkAsListed.add(queue.remove())
                    if (messageUidsAndMarkAsListed.size == Constants.MAX_DELETE_MESSAGE_ON_SERVER_BATCH_SIZE) {
                        break
                    }
                } while (!queue.isEmpty())
            }
        }
        return messageUidsAndMarkAsListed.toTypedArray<UidAndDeletedOrMarkAsListed>()
    }

    private fun scheduleNewDeleteMessageAndAttachmentsFromServerOperationQueueing(ownedIdentity: Identity) {
        scheduler.schedule(
            ownedIdentity,
            {
                queueNewDeleteMessageAndAttachmentsFromServerOperation(
                    ownedIdentity,
                    null,
                    DeleteOrMarkAsListed.DELETE_EVERYWHERE
                )
            },
            "DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    private fun waitForServerSession(
        ownedIdentity: Identity,
        messageUid: UID,
        markAsListed: DeleteOrMarkAsListed
    ) {
        awaitingServerSessionOperationsLock.lock()
        var list = awaitingServerSessionOperations[ownedIdentity]
        if (list == null) {
            list = ArrayList()
            awaitingServerSessionOperations[ownedIdentity] = list
        }
        list.add(IdentityAndUidAndDeletedOrMarkAsListed(ownedIdentity, messageUid, markAsListed))
        awaitingServerSessionOperationsLock.unlock()
    }


    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity =
            (operation as DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation).ownedIdentity
        scheduler.clearFailedCount(ownedIdentity)

        // if there are still some messages in the queue, reschedule a batch operation
        synchronized(messageUidsToDeleteByOwnedIdentity) {
            val queue = messageUidsToDeleteByOwnedIdentity[ownedIdentity]
            if (!queue.isNullOrEmpty()) {
                queueNewDeleteMessageAndAttachmentsFromServerOperation(ownedIdentity, null, DeleteOrMarkAsListed.DELETE_EVERYWHERE)
            }
        }
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity =
            (operation as DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation).ownedIdentity
        val messageUidsAndMarkAsListed = operation.messageUidsAndMarkAsListed
        var rfc = operation.reasonForCancel
        Logger.i("DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation cancelled for reason $rfc")
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation.RFC_INVALID_SERVER_SESSION -> {
                for (uidAndBoolean in messageUidsAndMarkAsListed) {
                    waitForServerSession(ownedIdentity, uidAndBoolean.uid, uidAndBoolean.deleteOrMarkAsListed)
                }
                createServerSessionDelegate.createServerSession(ownedIdentity)
            }

            else -> {
                // re-add all messageUids to the queue
                synchronized(messageUidsToDeleteByOwnedIdentity) {
                    var queue = messageUidsToDeleteByOwnedIdentity[ownedIdentity]
                    if (queue == null) {
                        queue = ArrayDeque<UidAndDeletedOrMarkAsListed>()
                        messageUidsToDeleteByOwnedIdentity[ownedIdentity] = queue
                    }
                    queue.addAll(messageUidsAndMarkAsListed)
                }
                scheduleNewDeleteMessageAndAttachmentsFromServerOperationQueueing(ownedIdentity)
            }
        }
    }

    internal inner class ServerSessionCreatedNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            if (notificationName != DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED) {
                return
            }
            val ownedIdentity =
                userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY)
            if (ownedIdentity !is Identity) {
                return
            }
            awaitingServerSessionOperationsLock.lock()
            val messageUids = awaitingServerSessionOperations[ownedIdentity]
            if (messageUids != null) {
                awaitingServerSessionOperations.remove(ownedIdentity)
                for (identityAndUidAndDeletedOrMarkAsListed in messageUids) {
                    queueNewDeleteMessageAndAttachmentsFromServerOperation(
                        ownedIdentity,
                        identityAndUidAndDeletedOrMarkAsListed.uid,
                        identityAndUidAndDeletedOrMarkAsListed.deleteOrMarkAsListed
                    )
                }
            }
            awaitingServerSessionOperationsLock.unlock()
        }
    }


    // Notifications received from MessageInbox when the message and its attachments can be deleted
    override fun messageCanBeDeletedFromServer(ownedIdentity: Identity?, messageUid: UID?) {
        if (ownedIdentity != null) {
            queueNewDeleteMessageAndAttachmentsFromServerOperation(ownedIdentity, messageUid, DeleteOrMarkAsListed.DELETE_EVERYWHERE)
        }
    }

    // Notifications received from MessageInbox when the payload is set and there are some attachments
    override fun messageCanBeMarkedAsListedOnServer(ownedIdentity: Identity?, messageUid: UID?, hasAttachments: Boolean) {
        if (ownedIdentity != null) {
            queueNewDeleteMessageAndAttachmentsFromServerOperation(ownedIdentity, messageUid, if (hasAttachments) DeleteOrMarkAsListed.MARK_AS_LISTED else DeleteOrMarkAsListed.DELETE_FROM_SERVER_BUT_NOT_LOCALLY)
        }
    }
}
