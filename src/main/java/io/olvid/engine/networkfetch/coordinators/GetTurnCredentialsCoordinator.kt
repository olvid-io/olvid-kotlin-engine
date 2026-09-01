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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.DownloadNotifications.TurnCredentialsFailedReason
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.WellKnownCacheDelegate
import io.olvid.engine.networkfetch.operations.GetTurnCredentialsOperation
import java.util.UUID
import javax.net.ssl.SSLSocketFactory


class GetTurnCredentialsCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    createServerSessionDelegate: CreateServerSessionDelegate,
    wellKnownCacheDelegate: WellKnownCacheDelegate
) : OnFinishCallback, OnCancelCallback {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val wellKnownCacheDelegate: WellKnownCacheDelegate
    private val createServerSessionDelegate: CreateServerSessionDelegate
    private val getTurnCredentialsOperationQueue: OperationQueue
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.createServerSessionDelegate = createServerSessionDelegate
        this.wellKnownCacheDelegate = wellKnownCacheDelegate

        getTurnCredentialsOperationQueue = OperationQueue(true)
    }

    fun startProcessing() {
        getTurnCredentialsOperationQueue.execute(1, "Engine-GetTurnCredentialsCoordinator")
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    private fun queueNewGetTurnCredentialsOperation(
        ownedIdentity: Identity,
        callUuid: UUID?,
        username1: String?,
        username2: String?
    ) {
        val op = GetTurnCredentialsOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            wellKnownCacheDelegate,
            ownedIdentity,
            callUuid,
            username1 ?: "",
            username2 ?: "",
            this,
            this
        )
        getTurnCredentialsOperationQueue.queue(op)
    }

    fun getTurnCredentials(
        ownedIdentity: Identity,
        callUuid: UUID?,
        username1: String?,
        username2: String?
    ) {
        queueNewGetTurnCredentialsOperation(ownedIdentity, callUuid, username1, username2)
    }


    override fun onFinishCallback(operation: Operation) {
        if (operation !is GetTurnCredentialsOperation) {
            return
        }

        val userInfo = HashMap<String, Any>()
        userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_OWNED_IDENTITY_KEY] = operation.ownedIdentity
        operation.callUuid?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_CALL_UUID_KEY] = it }
        operation.expiringUsername1?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_USERNAME_1_KEY] = it }
        operation.password1?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_PASSWORD_1_KEY] = it }
        operation.expiringUsername2?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_USERNAME_2_KEY] = it }
        operation.password2?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_PASSWORD_2_KEY] = it }
        operation.turnServers?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_SERVERS_KEY] = it }
        operation.altTurnServers?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_ALT_SERVERS_KEY] = it }

        if (notificationPostingDelegate != null) {
            notificationPostingDelegate?.postNotification(
                DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED,
                userInfo
            )
        }
    }

    override fun onCancelCallback(operation: Operation) {
        if (operation !is GetTurnCredentialsOperation) {
            return
        }
        var rfc = operation.reasonForCancel
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        val failedReason: TurnCredentialsFailedReason
        when (rfc) {
            GetTurnCredentialsOperation.RFC_INVALID_SERVER_SESSION -> {
                createServerSessionDelegate.createServerSession(operation.ownedIdentity)
                failedReason = TurnCredentialsFailedReason.BAD_SERVER_SESSION
            }

            GetTurnCredentialsOperation.RFC_PERMISSION_DENIED -> failedReason =
                TurnCredentialsFailedReason.PERMISSION_DENIED

            GetTurnCredentialsOperation.RFC_SERVER_DOES_NOT_SUPPORT_CALLS -> failedReason =
                TurnCredentialsFailedReason.CALLS_NOT_SUPPORTED_ON_SERVER

            GetTurnCredentialsOperation.RFC_WELL_KNOWN_NOT_CACHED, Operation.RFC_NULL -> failedReason =
                TurnCredentialsFailedReason.UNABLE_TO_CONTACT_SERVER

            else -> failedReason = TurnCredentialsFailedReason.UNABLE_TO_CONTACT_SERVER
        }
        val userInfo = HashMap<String, Any>()
        userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED_OWNED_IDENTITY_KEY] = operation.ownedIdentity
        operation.callUuid?.let { userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED_CALL_UUID_KEY] = it }
        userInfo[DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED_REASON_KEY] = failedReason
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED,
            userInfo
        )
    }
}
