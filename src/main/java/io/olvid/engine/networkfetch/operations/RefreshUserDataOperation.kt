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
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.containers.UserData
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory


class RefreshUserDataOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val label: UID,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    IdentityAndUid.computeUniqueUid(
        ownedIdentity,
        label
    ), onFinishCallback, onCancelCallback
) {
    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        val userData: UserData?
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    Logger.d("Starting RefreshUserDataOperation")
                    userData = fetchManagerSession.identityDelegate!!.getUserData(
                        fetchManagerSession.session,
                        ownedIdentity,
                        label
                    )
                    if (userData == null) {
                        cancel(RFC_USER_DATA_NOT_FOUND)
                        return
                    }

                    val serverSessionToken: ByteArray? =
                        ServerSession.getToken(fetchManagerSession, ownedIdentity)
                    if (serverSessionToken == null) {
                        cancel(RFC_INVALID_SERVER_SESSION)
                        return
                    }
                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = RefreshUserDataServerMethod(
                        ownedIdentity,
                        serverSessionToken,
                        label
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        fetchManagerSession.identityDelegate.isActiveOwnedIdentity(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    )

                    fetchManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            fetchManagerSession.identityDelegate.updateUserDataNextRefreshTimestamp(
                                fetchManagerSession.session,
                                ownedIdentity,
                                label
                            )
                            finished = true
                            return
                        }

                        ServerMethod.INVALID_SESSION -> {
                            ServerSession.deleteCurrentTokenIfEqualTo(
                                fetchManagerSession,
                                serverSessionToken,
                                ownedIdentity
                            )
                            fetchManagerSession.session.commit()
                            cancel(RFC_INVALID_SERVER_SESSION)
                            return
                        }

                        ServerMethod.DELETED_FROM_SERVER -> {
                            cancel(RFC_USER_DATA_DELETED_FROM_SERVER)
                            return
                        }

                        ServerMethod.IDENTITY_IS_NOT_ACTIVE -> {
                            cancel(RFC_IDENTITY_IS_INACTIVE)
                            return
                        }

                        else -> {
                            cancel(RFC_NETWORK_ERROR)
                            return
                        }
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

    companion object {
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_USER_DATA_NOT_FOUND: Int = 2
        const val RFC_INVALID_SERVER_SESSION: Int = 3
        const val RFC_IDENTITY_IS_INACTIVE: Int = 4
        const val RFC_USER_DATA_DELETED_FROM_SERVER: Int = 5
    }
}

internal class RefreshUserDataServerMethod(
    private val identity: Identity,
    private val token: ByteArray,
    private val label: UID
) : ServerMethod() {
    private val server: String

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
                Encoded.of(label),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        // Nothing to parse here
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/refreshUserData"
    }
}