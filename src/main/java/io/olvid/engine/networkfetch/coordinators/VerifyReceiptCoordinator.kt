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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.operations.VerifyReceiptOperation
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocketFactory


class VerifyReceiptCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate
) : OnCancelCallback {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val createServerSessionDelegate: CreateServerSessionDelegate

    private val verifyReceiptOperationQueue: OperationQueue

    private var notificationListeningDelegate: NotificationListeningDelegate? = null

    private val awaitingServerSessionOperations: HashMap<Identity?, String?>
    private val awaitingServerSessionOperationsLock: Lock
    private val serverSessionCreatedNotificationListener: ServerSessionCreatedNotificationListener


    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.createServerSessionDelegate = createServerSessionDelegate

        verifyReceiptOperationQueue = OperationQueue(true)

        awaitingServerSessionOperations = HashMap<Identity?, String?>()
        awaitingServerSessionOperationsLock = ReentrantLock()
        serverSessionCreatedNotificationListener = ServerSessionCreatedNotificationListener()
    }

    fun setNotificationListeningDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.notificationListeningDelegate = notificationListeningDelegate
        // register to NotificationCenter for NOTIFICATION_SERVER_SESSION_CREATED
        this.notificationListeningDelegate!!.addListener(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            serverSessionCreatedNotificationListener
        )
    }

    private fun queueNewVerifyReceiptOperation(ownedIdentity: Identity, storeToken: String) {
        val op = VerifyReceiptOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            storeToken,
            this
        )
        verifyReceiptOperationQueue.queue(op)
    }

    fun startProcessing() {
        verifyReceiptOperationQueue.execute(1, "Engine-VerifyReceiptCoordinator")
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity = (operation as VerifyReceiptOperation).ownedIdentity
        val storeToken = operation.storeToken
        var rfc = operation.reasonForCancel
        Logger.i("VerifyReceiptOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            VerifyReceiptOperation.RFC_INVALID_SERVER_SESSION -> {
                waitForServerSession(ownedIdentity, storeToken)
                createServerSessionDelegate.createServerSession(ownedIdentity)
            }
        }
    }


    private fun waitForServerSession(identity: Identity?, storeToken: String?) {
        awaitingServerSessionOperationsLock.lock()
        awaitingServerSessionOperations.put(identity, storeToken)
        awaitingServerSessionOperationsLock.unlock()
    }

    internal inner class ServerSessionCreatedNotificationListener : NotificationListener {
        override fun callback(notificationName: String?, userInfo: Map<String, Any>?) {
            if (notificationName != DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED) {
                return
            }
            val identityObject =
                userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY)
            if (identityObject !is Identity) {
                return
            }
            val ownedIdentity = identityObject
            awaitingServerSessionOperationsLock.lock()
            val storeToken = awaitingServerSessionOperations.get(ownedIdentity)
            if (storeToken != null) {
                awaitingServerSessionOperations.remove(ownedIdentity)
                queueNewVerifyReceiptOperation(ownedIdentity, storeToken)
            }
            awaitingServerSessionOperationsLock.unlock()
        }
    }


    fun verifyReceipt(ownedIdentity: Identity, storeToken: String?) {
        if (storeToken == null) return
        queueNewVerifyReceiptOperation(ownedIdentity, storeToken)
    }
}
