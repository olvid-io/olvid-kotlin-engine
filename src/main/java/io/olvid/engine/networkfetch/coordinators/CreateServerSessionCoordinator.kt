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
import io.olvid.engine.datatypes.NoDuplicateOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.SolveChallengeDelegate
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.CreateServerSessionDelegate
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.operations.CreateServerSessionCompositeOperation
import io.olvid.engine.networkfetch.operations.QueryApiKeyStatusOperation
import java.util.UUID
import javax.net.ssl.SSLSocketFactory


class CreateServerSessionCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?
) : OnFinishCallback, OnCancelCallback, CreateServerSessionDelegate {
    private val scheduler: ExponentialBackoffRepeatingScheduler<Identity?>
    private val createServerSessionOperationQueue: NoDuplicateOperationQueue
    private val queryApiKeyStatusOperationQueue: OperationQueue

    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private var solveChallengeDelegate: SolveChallengeDelegate?
    private var notificationPostingDelegate: NotificationPostingDelegate? = null

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.solveChallengeDelegate = null

        scheduler = ExponentialBackoffRepeatingScheduler<Identity?>()
        createServerSessionOperationQueue = NoDuplicateOperationQueue()

        queryApiKeyStatusOperationQueue = OperationQueue(true)
    }

    fun startProcessing() {
        createServerSessionOperationQueue.execute(1, "Engine-CreateServerSessionCoordinator")
        queryApiKeyStatusOperationQueue.execute(
            1,
            "Engine-CreateServerSessionCoordinator-QueryApiKeyStatus"
        )
    }

    fun setNotificationPostingDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    fun setSolveChallengeDelegate(solveChallengeDelegate: SolveChallengeDelegate?) {
        this.solveChallengeDelegate = solveChallengeDelegate
    }

    fun initialQueueing() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                for (serverSession in ServerSession.getAll(fetchManagerSession)) {
                    if (!fetchManagerSession.identityDelegate!!.isOwnedIdentity(
                            fetchManagerSession.session,
                            serverSession!!.getOwnedIdentity(),
                            true
                        )
                    ) {
                        // owned identity does not exist --> delete the session
                        serverSession.delete()
                    } else {
                        // post notification of apiKey status
                        val userInfo = HashMap<String, Any>()
                        userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY] = serverSession.getOwnedIdentity()
                        userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_STATUS_KEY] = serverSession.getApiKeyStatus()
                        userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_PERMISSIONS_KEY] = serverSession.getPermissions()
                        userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_EXPIRATION_TIMESTAMP_KEY] = serverSession.apiKeyExpirationTimestamp
                        notificationPostingDelegate?.postNotification(
                            DownloadNotifications.NOTIFICATION_SERVER_SESSION_EXISTS,
                            userInfo
                        )
                    }
                }
                fetchManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    fun queueNewQueryApiKeyStatusOperation(ownedIdentity: Identity?, apiKey: UUID?) {
        val op = QueryApiKeyStatusOperation(
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity!!,
            apiKey,
            OnFinishCallback { operation: Operation? ->
                if (notificationPostingDelegate == null) {
                    Logger.e("NotificationPostingDelegate not set onFinishCallback of QueryApiKeyStatusOperation.")
                    return@OnFinishCallback
                }
                val apiKeyStatus = (operation as QueryApiKeyStatusOperation).apiKeyStatus
                val permissions = operation.permissions
                val apiKeyExpirationTimestamp = operation.apiKeyExpirationTimestamp

                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_OWNED_IDENTITY_KEY] = ownedIdentity
                apiKey?.let { userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_KEY] = it }
                apiKeyStatus?.let { userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] = it }
                permissions?.let { userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_PERMISSIONS_KEY] = it }
                userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_EXPIRATION_TIMESTAMP_KEY] = apiKeyExpirationTimestamp
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS,
                    userInfo
                )
            },
            OnCancelCallback { operation: Operation? ->
                if (notificationPostingDelegate == null) {
                    Logger.e("NotificationPostingDelegate not set onCancelCallback of QueryApiKeyStatusOperation.")
                    return@OnCancelCallback
                }
                val userInfo = HashMap<String, Any>()
                userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED_OWNED_IDENTITY_KEY] = ownedIdentity
                apiKey?.let { userInfo[DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED_API_KEY_KEY] = it }
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED,
                    userInfo
                )
            })
        queryApiKeyStatusOperationQueue.queue(op)
    }

    private fun queueNewCreateServerSessionCompositeOperation(ownedIdentity: Identity) {
        if (solveChallengeDelegate == null) {
            Logger.e("The SolveChallengeDelegate is not set in the CreateServerSessionCoordinator. Unable to queue a new CreateServerSessionCompositeOperation.")
            return
        }
        val op = CreateServerSessionCompositeOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            solveChallengeDelegate,
            this,
            this
        )
        createServerSessionOperationQueue.queue(op)
    }

    private fun scheduleNewCreateServerSessionCompositeOperationQueueing(ownedIdentity: Identity) {
        scheduler.schedule(
            ownedIdentity,
            Runnable { queueNewCreateServerSessionCompositeOperation(ownedIdentity) },
            "CreateServerSessionCompositeOperation"
        )
    }

    fun retryScheduledNetworkTasks() {
        scheduler.retryScheduledRunnables()
    }

    override fun onFinishCallback(operation: Operation) {
        val ownedIdentity = (operation as CreateServerSessionCompositeOperation).ownedIdentity
        val apiKeyStatus = operation.apiKeyStatus
        val permissions = operation.permissions
        val apiKeyExpirationTimestamp = operation.apiKeyExpirationTimestamp

        scheduler.clearFailedCount(ownedIdentity)
        val userInfo = HashMap<String, Any>()
        userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY] = ownedIdentity
        // apiKeyStatus/permissions are null when the session already had a valid token; omit them
        // rather than `as Any` (which threw "null cannot be cast to non-null type kotlin.Any").
        apiKeyStatus?.let { userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_STATUS_KEY] = it }
        permissions?.let { userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_PERMISSIONS_KEY] = it }
        userInfo[DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_EXPIRATION_TIMESTAMP_KEY] = apiKeyExpirationTimestamp
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
            userInfo
        )
    }

    override fun onCancelCallback(operation: Operation) {
        val ownedIdentity = (operation as CreateServerSessionCompositeOperation).ownedIdentity
        var rfc = operation.reasonForCancel
        Logger.i("CreateServerSessionCompositeOperation cancelled for reason " + rfc)
        if (rfc == null) {
            rfc = Operation.RFC_NULL
        }
        when (rfc) {
            CreateServerSessionCompositeOperation.RFC_SESSION_CANNOT_BE_FOUND -> queueNewCreateServerSessionCompositeOperation(
                ownedIdentity
            )

            CreateServerSessionCompositeOperation.RFC_IDENTITY_NOT_FOUND -> {}
            CreateServerSessionCompositeOperation.RFC_INVALID_SESSION -> scheduleNewCreateServerSessionCompositeOperationQueueing(
                ownedIdentity
            )

            else -> scheduleNewCreateServerSessionCompositeOperationQueueing(ownedIdentity)
        }
    }


    override fun createServerSession(ownedIdentity: Identity?) {
        queueNewCreateServerSessionCompositeOperation(ownedIdentity!!)
    }
}
