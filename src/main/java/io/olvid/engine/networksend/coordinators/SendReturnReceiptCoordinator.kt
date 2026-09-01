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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ExponentialBackoffRepeatingScheduler
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.containers.IdentityAndLong
import io.olvid.engine.datatypes.containers.StringAndLong
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networksend.databases.ReturnReceipt
import io.olvid.engine.networksend.databases.ReturnReceipt.NewReturnReceiptListener
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import io.olvid.engine.networksend.operations.UploadReturnReceiptOperation
import java.sql.SQLException
import java.util.ArrayDeque
import java.util.Arrays
import java.util.Queue
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class SendReturnReceiptCoordinator(
    sendManagerSessionFactory: SendManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    prng: PRNGService?,
    @Suppress("UNUSED_PARAMETER") threadCount: Int
) : NewReturnReceiptListener, OnCancelCallback, OnFinishCallback {
    private val sendManagerSessionFactory: SendManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    private val prng: PRNGService?
    private val returnReceiptOwnedIdentityAndIdByServer: HashMap<String?, Queue<IdentityAndLong?>?>
    private val sendReturnReceiptOperationQueue: NoDuplicateOperationQueue
    private val scheduler: ExponentialBackoffRepeatingScheduler<String?>

    private val awaitingIdentityReactivationOperations: HashMap<Identity?, MutableList<StringAndLong?>?>
    private val awaitingIdentityReactivationOperationsLock: Lock

    private val notificationListener: NotificationListener

    init {
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.prng = prng

        returnReceiptOwnedIdentityAndIdByServer = HashMap<String?, Queue<IdentityAndLong?>?>()
        sendReturnReceiptOperationQueue = NoDuplicateOperationQueue()

        scheduler = ExponentialBackoffRepeatingScheduler<String?>()

        awaitingIdentityReactivationOperations = HashMap<Identity?, MutableList<StringAndLong?>?>()
        awaitingIdentityReactivationOperationsLock = ReentrantLock()

        notificationListener = NotificationListener()
    }

    fun startProcessing() {
        sendReturnReceiptOperationQueue.execute(1, "Engine-SendReturnReceiptCoordinator")
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
                val returnReceipts: Array<ReturnReceipt?> =
                    ReturnReceipt.getAll(sendManagerSession)
                for (returnReceipt in returnReceipts) {
                    if (returnReceipt == null) continue
                    queueNewSendReturnReceiptOperation(
                        returnReceipt.getContactIdentity().server,
                        returnReceipt.getOwnedIdentity(),
                        returnReceipt.id
                    )
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    private fun queueNewSendReturnReceiptOperation(
        server: String?,
        ownedIdentity: Identity?,
        returnReceiptId: Long
    ) {
        if (ownedIdentity != null) {
            synchronized(returnReceiptOwnedIdentityAndIdByServer) {
                var queue = returnReceiptOwnedIdentityAndIdByServer.get(server)
                if (queue == null) {
                    queue = ArrayDeque<IdentityAndLong?>()
                    returnReceiptOwnedIdentityAndIdByServer.put(server, queue)
                }
                queue.add(IdentityAndLong(ownedIdentity, returnReceiptId))
            }
        }
        val op = UploadReturnReceiptOperation(
            sendManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            server ?: return,
            object : ReturnReceiptBatchProvider {
                override val batchOFReturnReceiptIds: Array<IdentityAndLong?>?
                    get() {
                        val returnReceiptOwnedIdentityAndId: MutableList<IdentityAndLong?> =
                            ArrayList<IdentityAndLong?>()
                        synchronized(returnReceiptOwnedIdentityAndIdByServer) {
                            val queue = returnReceiptOwnedIdentityAndIdByServer.get(server)
                            if (queue != null && !queue.isEmpty()) {
                                do {
                                    returnReceiptOwnedIdentityAndId.add(queue.remove())
                                    if (returnReceiptOwnedIdentityAndId.size == Constants.MAX_UPLOAD_RETURN_RECEIPT_BATCH_SIZE) {
                                        break
                                    }
                                } while (!queue.isEmpty())
                            }
                        }
                        return returnReceiptOwnedIdentityAndId.toTypedArray<IdentityAndLong?>()
                    }
            },
            this,
            this
        )
        sendReturnReceiptOperationQueue.queue(op)
    }

    private fun scheduleNewSendReturnReceiptOperation(server: String?) {
        scheduler.schedule(
            server,
            Runnable { queueNewSendReturnReceiptOperation(server, null, 0) },
            "UploadReturnReceiptOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    private fun waitForIdentityReactivation(ownedIdentity: Identity?, server: String, id: Long) {
        awaitingIdentityReactivationOperationsLock.lock()
        var list = awaitingIdentityReactivationOperations.get(ownedIdentity)
        if (list == null) {
            list = ArrayList<StringAndLong?>()
            awaitingIdentityReactivationOperations.put(ownedIdentity, list)
        }
        list.add(StringAndLong(server, id))
        awaitingIdentityReactivationOperationsLock.unlock()
    }


    override fun onFinishCallback(operation: Operation) {
        val server = (operation as UploadReturnReceiptOperation).server
        val identityInactiveReturnReceiptIds = operation.identityInactiveReturnReceiptIds
        scheduler.clearFailedCount(server)

        // if there are still some messages in the queue, reschedule a batch operation
        synchronized(returnReceiptOwnedIdentityAndIdByServer) {
            val queue = returnReceiptOwnedIdentityAndIdByServer.get(server)
            if (queue != null && !queue.isEmpty()) {
                queueNewSendReturnReceiptOperation(server, null, 0)
            }
        }

        // handle message the operations couldn't because of inactive identity
        for (identityAndLong in identityInactiveReturnReceiptIds) {
            if (identityAndLong == null) continue
            waitForIdentityReactivation(identityAndLong.identity, server, identityAndLong.lng)
        }
    }

    override fun onCancelCallback(operation: Operation) {
        val server = (operation as UploadReturnReceiptOperation).server
        val returnReceiptOwnedIdentitiesAndIds = operation.returnReceiptOwnedIdentitiesAndIds
        val rfc = operation.reasonForCancel
        Logger.i("UploadReturnReceiptOperation cancelled for reason $rfc")

        synchronized(returnReceiptOwnedIdentityAndIdByServer) {
            var queue = returnReceiptOwnedIdentityAndIdByServer.get(server)
            if (queue == null) {
                queue = ArrayDeque<IdentityAndLong?>()
                returnReceiptOwnedIdentityAndIdByServer[server] = queue
            }
            queue.addAll(returnReceiptOwnedIdentitiesAndIds)
        }
        scheduleNewSendReturnReceiptOperation(server)
    }

    // Notification received from OutboxAttachment database
    override fun newReturnReceipt(
        server: String?,
        ownedIdentity: Identity?,
        returnReceiptId: Long
    ) {
        queueNewSendReturnReceiptOperation(server, ownedIdentity, returnReceiptId)
    }


    interface ReturnReceiptBatchProvider {
        val batchOFReturnReceiptIds: Array<IdentityAndLong?>?
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
                    for (serverAndId in list) {
                        if (serverAndId != null) {
                            queueNewSendReturnReceiptOperation(
                                serverAndId.string,
                                ownedIdentity,
                                serverAndId.lng
                            )
                        }
                    }
                }
                awaitingIdentityReactivationOperationsLock.unlock()
            }
        }
    }
}
