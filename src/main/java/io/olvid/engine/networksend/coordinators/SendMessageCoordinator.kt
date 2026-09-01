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
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.containers.StringAndBoolean
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.databases.OutboxMessage.NewOutboxMessageListener
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import io.olvid.engine.networksend.operations.BatchUploadMessagesCompositeOperation
import io.olvid.engine.networksend.operations.UploadMessageCompositeOperation
import java.sql.SQLException
import java.util.ArrayDeque
import java.util.Arrays
import java.util.Queue
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class SendMessageCoordinator(
    sendManagerSessionFactory: SendManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    @Suppress("UNUSED_PARAMETER") threadCount: Int
) : NewOutboxMessageListener {
    private val sendManagerSessionFactory: SendManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?

    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    private val sendMessageWithAttachmentOperationQueue: OperationQueue
    private val scheduler: ExponentialBackoffRepeatingScheduler<IdentityAndUid?>

    private val userContentMessageUidsByServer: HashMap<String?, Queue<IdentityAndUid?>?>
    private val batchSendUserContentMessageOperationQueue: NoDuplicateOperationQueue
    private val protocolMessageUidsByServer: HashMap<String?, Queue<IdentityAndUid?>?>
    private val batchSendProtocolMessageOperationQueue: NoDuplicateOperationQueue
    private val batchScheduler: ExponentialBackoffRepeatingScheduler<StringAndBoolean?>

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<UID?>?>
    private val awaitingIdentityReactivationOperationsLock: Lock

    private val notificationListener: NotificationListener


    init {
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride

        sendMessageWithAttachmentOperationQueue = OperationQueue(true)

        scheduler = ExponentialBackoffRepeatingScheduler<IdentityAndUid?>()


        userContentMessageUidsByServer = HashMap<String?, Queue<IdentityAndUid?>?>()
        batchSendUserContentMessageOperationQueue = NoDuplicateOperationQueue()

        protocolMessageUidsByServer = HashMap<String?, Queue<IdentityAndUid?>?>()
        batchSendProtocolMessageOperationQueue = NoDuplicateOperationQueue()

        batchScheduler = ExponentialBackoffRepeatingScheduler<StringAndBoolean?>()


        awaitingIdentityReactivationOperations = HashMap<Identity?, MutableList<UID?>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()

        notificationListener = NotificationListener()
    }

    fun startProcessing() {
        sendMessageWithAttachmentOperationQueue.execute(
            1,
            "Engine-SendMessageCoordinator-WithAttachment"
        )
        batchSendUserContentMessageOperationQueue.execute(
            1,
            "Engine-SendMessageCoordinator-WithUserContent"
        )
        batchSendProtocolMessageOperationQueue.execute(1, "Engine-SendMessageCoordinator-Protocol")
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
                val outboxMessages: Array<OutboxMessage?> =
                    OutboxMessage.getAll(sendManagerSession)
                for (outboxMessage in outboxMessages) {
                    if (outboxMessage == null) continue
                    queueNewSendMessageCompositeOperation(
                        outboxMessage.server,
                        outboxMessage.getOwnedIdentity(),
                        outboxMessage.uid,
                        outboxMessage.attachments?.isNotEmpty() == true,
                        outboxMessage.isApplicationMessage
                    )
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    private fun queueNewSendMessageCompositeOperation(
        server: String?,
        ownedIdentity: Identity?,
        messageUid: UID?,
        hasAttachment: Boolean,
        hasUserContent: Boolean
    ) {
        if (hasAttachment || server == null) {
            val op = UploadMessageCompositeOperation(
                sendManagerSessionFactory,
                sslSocketFactory,
                userAgentOverride,
                ownedIdentity ?: return,
                messageUid ?: return,
                OnFinishCallback { operation: Operation? ->
                    this.onFinishCallbackWithAttachment(operation!!)
                },
                OnCancelCallback { operation: Operation? ->
                    this.onCancelCallbackWithAttachment(operation!!)
                })
            sendMessageWithAttachmentOperationQueue.queue(op)
        } else if (hasUserContent) {
            if (ownedIdentity != null && messageUid != null) {
                synchronized(userContentMessageUidsByServer) {
                    var queue = userContentMessageUidsByServer.get(server)
                    if (queue == null) {
                        queue = ArrayDeque<IdentityAndUid?>()
                        userContentMessageUidsByServer.put(server, queue)
                    }
                    queue.add(IdentityAndUid(ownedIdentity, messageUid))
                }
            }
            val op = BatchUploadMessagesCompositeOperation(
                sendManagerSessionFactory,
                sslSocketFactory,
                userAgentOverride,
                server,
                true,
                object : MessageBatchProvider {
                    override val batchOFMessageUids: Array<IdentityAndUid?>?
                        get() {
                            val messageIdentitiesAndUids: MutableList<IdentityAndUid?> =
                                ArrayList<IdentityAndUid?>()
                            synchronized(userContentMessageUidsByServer) {
                                val queue = userContentMessageUidsByServer.get(server)
                                if (queue != null && !queue.isEmpty()) {
                                    do {
                                        messageIdentitiesAndUids.add(queue.remove())
                                        if (messageIdentitiesAndUids.size == Constants.MAX_UPLOAD_MESSAGE_BATCH_SIZE) {
                                            break
                                        }
                                    } while (!queue.isEmpty())
                                }
                            }
                            return messageIdentitiesAndUids.toTypedArray<IdentityAndUid?>()
                        }
                },
                OnFinishCallback { operation: Operation? ->
                    this.onFinishCallbackUserContent(operation!!)
                },
                OnCancelCallback { operation: Operation? ->
                    this.onCancelCallbackUserContent(operation!!)
                })
            batchSendUserContentMessageOperationQueue.queue(op)
        } else {
            if (ownedIdentity != null && messageUid != null) {
                synchronized(protocolMessageUidsByServer) {
                    var queue = protocolMessageUidsByServer.get(server)
                    if (queue == null) {
                        queue = ArrayDeque<IdentityAndUid?>()
                        protocolMessageUidsByServer.put(server, queue)
                    }
                    queue.add(IdentityAndUid(ownedIdentity, messageUid))
                }
            }
            val op = BatchUploadMessagesCompositeOperation(
                sendManagerSessionFactory,
                sslSocketFactory,
                userAgentOverride,
                server,
                false,
                object : MessageBatchProvider {
                    override val batchOFMessageUids: Array<IdentityAndUid?>?
                        get() {
                            val messageIdentitiesAndUids: MutableList<IdentityAndUid?> =
                                ArrayList<IdentityAndUid?>()
                            synchronized(protocolMessageUidsByServer) {
                                val queue = protocolMessageUidsByServer.get(server)
                                if (queue != null && !queue.isEmpty()) {
                                    do {
                                        messageIdentitiesAndUids.add(queue.remove())
                                        if (messageIdentitiesAndUids.size == Constants.MAX_UPLOAD_MESSAGE_BATCH_SIZE) {
                                            break
                                        }
                                    } while (!queue.isEmpty())
                                }
                            }
                            return messageIdentitiesAndUids.toTypedArray<IdentityAndUid?>()
                        }
                },
                OnFinishCallback { operation: Operation? -> this.onFinishCallbackProtocol(operation!!) },
                OnCancelCallback { operation: Operation? -> this.onCancelCallbackProtocol(operation!!) })
            batchSendProtocolMessageOperationQueue.queue(op)
        }
    }

    private fun scheduleNewSendMessageCompositeOperationQueueing(
        ownedIdentity: Identity,
        messageUid: UID
    ) {
        scheduler.schedule(
            IdentityAndUid(ownedIdentity, messageUid),
            Runnable {
                queueNewSendMessageCompositeOperation(
                    null,
                    ownedIdentity,
                    messageUid,
                    true,
                    true
                )
            },
            "UploadMessageCompositeOperation"
        )
    }

    private fun scheduleNewBatchSendMessageCompositeOperationQueueing(
        server: String,
        hasUserContent: Boolean
    ) {
        batchScheduler.schedule(
            StringAndBoolean(server, hasUserContent),
            Runnable {
                queueNewSendMessageCompositeOperation(
                    server,
                    null,
                    null,
                    false,
                    hasUserContent
                )
            },
            "BatchUploadMessagesCompositeOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
        batchScheduler.retryScheduledRunnables()
    }

    private fun waitForIdentityReactivation(ownedIdentity: Identity?, messageUid: UID?) {
        awaitingIdentityReactivationOperationsLock.lock()
        var list = awaitingIdentityReactivationOperations.get(ownedIdentity)
        if (list == null) {
            list = ArrayList<UID?>()
            awaitingIdentityReactivationOperations.put(ownedIdentity, list)
        }
        list.add(messageUid)
        awaitingIdentityReactivationOperationsLock.unlock()
    }


    fun onFinishCallbackProtocol(operation: Operation) {
        val server = (operation as BatchUploadMessagesCompositeOperation).server
        val identityInactiveMessageUids = operation.identityInactiveMessageUids
        val tooManyHeadersUnsentMessageUids = operation.tooManyHeadersUnsentMessageUids
        batchScheduler.clearFailedCount(StringAndBoolean(server, false))

        // if the batch was truncated because of too many headers, re-queue the remaining ones
        if (tooManyHeadersUnsentMessageUids != null && !tooManyHeadersUnsentMessageUids.isEmpty()) {
            Logger.i("A batch of messages contained too many headers, using a smaller batch.")
            synchronized(protocolMessageUidsByServer) {
                var queue = protocolMessageUidsByServer.get(server)
                if (queue == null) {
                    queue = ArrayDeque<IdentityAndUid?>()
                    protocolMessageUidsByServer.put(server, queue)
                }
                queue.addAll(tooManyHeadersUnsentMessageUids)
            }
        }

        // if there are still some messages in the queue, reschedule a batch operation
        synchronized(protocolMessageUidsByServer) {
            val queue = protocolMessageUidsByServer.get(server)
            if (queue != null && !queue.isEmpty()) {
                queueNewSendMessageCompositeOperation(server, null, null, false, false)
            }
        }

        // handle message the operations couldn't because of inactive identity
        for (identityAndUid in identityInactiveMessageUids!!) {
            waitForIdentityReactivation(identityAndUid?.identity, identityAndUid?.uid)
        }
    }

    fun onCancelCallbackProtocol(operation: Operation) {
        val server = (operation as BatchUploadMessagesCompositeOperation).server
        val identityAndMessageUids = operation.messageIdentitiesAndUids
        var rfc = operation.reasonForCancel
        Logger.i("BatchUploadMessagesCompositeOperation (protocol) cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            BatchUploadMessagesCompositeOperation.RFC_BATCH_TOO_LARGE -> if (identityAndMessageUids != null) {
                // if the payload is too large when batching, queue each message individually
                for (identityAndMessageUid in identityAndMessageUids) {
                    queueNewSendMessageCompositeOperation(
                        null,
                        identityAndMessageUid?.identity,
                        identityAndMessageUid?.uid,
                        true,
                        true
                    )
                }
            }

            else -> {
                // re-add all messageUids to the queue and schedule a new operation later
                if (identityAndMessageUids != null) {
                    synchronized(protocolMessageUidsByServer) {
                        var queue = protocolMessageUidsByServer.get(server)
                        if (queue == null) {
                            queue = ArrayDeque<IdentityAndUid?>()
                            protocolMessageUidsByServer.put(server, queue)
                        }
                        queue.addAll(Arrays.asList<IdentityAndUid?>(*identityAndMessageUids))
                    }
                }
                scheduleNewBatchSendMessageCompositeOperationQueueing(server, false)
            }
        }
    }

    fun onFinishCallbackUserContent(operation: Operation) {
        val server = (operation as BatchUploadMessagesCompositeOperation).server
        val identityInactiveMessageUids = operation.identityInactiveMessageUids
        val tooManyHeadersUnsentMessageUids = operation.tooManyHeadersUnsentMessageUids
        batchScheduler.clearFailedCount(StringAndBoolean(server, true))

        // if the batch was truncated because of too many headers, re-queue the remaining ones
        if (tooManyHeadersUnsentMessageUids != null && !tooManyHeadersUnsentMessageUids.isEmpty()) {
            Logger.i("A batch of messages contained too many headers, using a smaller batch.")
            synchronized(userContentMessageUidsByServer) {
                var queue = userContentMessageUidsByServer.get(server)
                if (queue == null) {
                    queue = ArrayDeque<IdentityAndUid?>()
                    userContentMessageUidsByServer.put(server, queue)
                }
                queue.addAll(tooManyHeadersUnsentMessageUids)
            }
        }

        // if there are still some messages in the queue, reschedule a batch operation
        synchronized(userContentMessageUidsByServer) {
            val queue = userContentMessageUidsByServer.get(server)
            if (queue != null && !queue.isEmpty()) {
                queueNewSendMessageCompositeOperation(server, null, null, false, true)
            }
        }

        // handle message the operations couldn't because of inactive identity
        for (identityAndUid in identityInactiveMessageUids!!) {
            waitForIdentityReactivation(identityAndUid?.identity, identityAndUid?.uid)
        }
    }

    fun onCancelCallbackUserContent(operation: Operation) {
        val server = (operation as BatchUploadMessagesCompositeOperation).server
        val identityAndMessageUids = operation.messageIdentitiesAndUids
        var rfc = operation.reasonForCancel
        Logger.i("BatchUploadMessagesCompositeOperation (user content) cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            BatchUploadMessagesCompositeOperation.RFC_BATCH_TOO_LARGE -> if (identityAndMessageUids != null) {
                // if the payload is too large when batching, queue each message individually
                for (identityAndMessageUid in identityAndMessageUids) {
                    queueNewSendMessageCompositeOperation(
                        null,
                        identityAndMessageUid?.identity,
                        identityAndMessageUid?.uid,
                        true,
                        true
                    )
                }
            }

            else -> {
                // re-add all messageUids to the queue
                if (identityAndMessageUids != null) {
                    synchronized(userContentMessageUidsByServer) {
                        var queue = userContentMessageUidsByServer.get(server)
                        if (queue == null) {
                            queue = ArrayDeque<IdentityAndUid?>()
                            userContentMessageUidsByServer.put(server, queue)
                        }
                        queue.addAll(Arrays.asList<IdentityAndUid?>(*identityAndMessageUids))
                    }
                }
                scheduleNewBatchSendMessageCompositeOperationQueueing(server, true)
            }
        }
    }

    fun onFinishCallbackWithAttachment(operation: Operation) {
        val ownedIdentity = (operation as UploadMessageCompositeOperation).ownedIdentity
        val messageUid = operation.messageUid
        scheduler.clearFailedCount(IdentityAndUid(ownedIdentity, messageUid))
    }

    fun onCancelCallbackWithAttachment(operation: Operation) {
        val ownedIdentity = (operation as UploadMessageCompositeOperation).ownedIdentity
        val messageUid = operation.messageUid
        var rfc = operation.reasonForCancel
        Logger.i("UploadMessageCompositeOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            UploadMessageCompositeOperation.RFC_MESSAGE_NOT_FOUND_IN_DATABASE -> {}
            UploadMessageCompositeOperation.RFC_IDENTITY_IS_INACTIVE -> waitForIdentityReactivation(
                ownedIdentity,
                messageUid
            )

            else -> scheduleNewSendMessageCompositeOperationQueueing(ownedIdentity, messageUid)
        }
    }

    // Notification received from OutboxMessage database
    override fun newMessageToSend(
        server: String?,
        ownedIdentity: Identity?,
        messageUid: UID?,
        hasAttachment: Boolean,
        hasUserContent: Boolean
    ) {
        queueNewSendMessageCompositeOperation(
            server,
            ownedIdentity,
            messageUid,
            hasAttachment,
            hasUserContent
        )
    }

    interface MessageBatchProvider {
        val batchOFMessageUids: Array<IdentityAndUid?>?
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
                val messageUids = awaitingIdentityReactivationOperations.get(ownedIdentity)
                if (messageUids != null) {
                    awaitingIdentityReactivationOperations.remove(ownedIdentity)
                    for (messageUid in messageUids) {
                        // if unsure, queue in the traditional message upload queue, even if there is no attachment
                        queueNewSendMessageCompositeOperation(
                            null,
                            ownedIdentity,
                            messageUid,
                            true,
                            true
                        )
                    }
                }
                awaitingIdentityReactivationOperationsLock.unlock()
            }
        }
    }
}
