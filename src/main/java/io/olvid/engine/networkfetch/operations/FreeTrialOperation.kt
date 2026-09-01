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
package io.olvid.engine.networkfetch.operations

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException
import java.util.UUID
import javax.net.ssl.SSLSocketFactory


class FreeTrialOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val ownedIdentity: Identity,
    private val retrieveApiKey: Boolean
) : Operation(
    ownedIdentity.computeUniqueUid(), null, null
) {
    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    val serverSessionToken: ByteArray? =
                        ServerSession.getToken(fetchManagerSession, ownedIdentity)
                    if (serverSessionToken != null) {
                        val serverMethod = FreeTrialServerMethod(
                            ownedIdentity,
                            serverSessionToken,
                            retrieveApiKey
                        )
                        serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                        val returnStatus = serverMethod.execute(
                            fetchManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                                fetchManagerSession.session,
                                ownedIdentity
                            )
                        )

                        fetchManagerSession.session.startTransaction()
                        when (returnStatus) {
                            ServerMethod.OK -> {
                                if (retrieveApiKey) {
                                    val userInfo = HashMap<String, Any>()
                                    userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS_OWNED_IDENTITY_KEY] = ownedIdentity
                                    fetchManagerSession.notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS,
                                        userInfo
                                    )

                                    ServerSession.deleteForIdentity(
                                        fetchManagerSession,
                                        ownedIdentity
                                    )
                                    fetchManagerSession.createServerSessionDelegate!!.createServerSession(
                                        ownedIdentity
                                    )
                                } else {
                                    val userInfo = HashMap<String, Any>()
                                    userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_OWNED_IDENTITY_KEY] = ownedIdentity
                                    userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY] = true
                                    fetchManagerSession.notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS,
                                        userInfo
                                    )
                                }
                                finished = true
                                return
                            }

                            ServerMethod.FREE_TRIAL_ALREADY_USED -> {
                                if (!retrieveApiKey) {
                                    val userInfo = HashMap<String, Any>()
                                    userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_OWNED_IDENTITY_KEY] = ownedIdentity
                                    userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY] = false
                                    fetchManagerSession.notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS,
                                        userInfo
                                    )
                                    finished = true
                                    return
                                }
                            }

                            ServerMethod.INVALID_SESSION -> {
                                ServerSession.deleteCurrentTokenIfEqualTo(
                                    fetchManagerSession,
                                    serverSessionToken,
                                    ownedIdentity
                                )
                                fetchManagerSession.session.commit()
                            }
                        }
                    }

                    // did not get an OK response --> notify failed
                    if (retrieveApiKey) {
                        val userInfo = HashMap<String, Any>()
                        userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED_OWNED_IDENTITY_KEY] = ownedIdentity
                        fetchManagerSession.notificationPostingDelegate?.postNotification(
                            DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED,
                            userInfo
                        )
                    } else {
                        val userInfo = HashMap<String, Any>()
                        userInfo[DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_FAILED_OWNED_IDENTITY_KEY] = ownedIdentity
                        fetchManagerSession.notificationPostingDelegate?.postNotification(
                            DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_FAILED,
                            userInfo
                        )
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                    fetchManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        fetchManagerSession.session.commit()
                        setFinished()
                    } else {
                        if (hasNoReasonForCancel()) {
                            cancel(null)
                        }
                        processCancel()
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            cancel(null)
            processCancel()
        }
    }
}

internal class FreeTrialServerMethod(
    private val identity: Identity,
    private val token: ByteArray,
    private val retrieveApiKey: Boolean
) : ServerMethod() {
    private val server: String

    var apiKey: UUID? = null
        private set

    init {
        this.server = identity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(token),
                Encoded.of(retrieveApiKey),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                if (retrieveApiKey) {
                    this.apiKey = receivedData!![0]!!.decodeUuid()
                }
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/freeTrial"
    }
}
