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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.coordinators.WellKnownCoordinator.NotCachedException
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.WellKnownCacheDelegate
import java.sql.SQLException
import java.util.UUID
import javax.net.ssl.SSLSocketFactory


class GetTurnCredentialsOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val wellKnownCacheDelegate: WellKnownCacheDelegate,
    @JvmField val ownedIdentity: Identity,
    @JvmField val callUuid: UUID?,
    private val username1: String,
    private val username2: String,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    ownedIdentity.computeUniqueUid(), onFinishCallback, onCancelCallback
) {
    var turnServers: MutableList<String>? = null
        private set
    var altTurnServers: MutableList<String>? = null
        private set
    var expiringUsername1: String? = null
        private set
    var password1: String? = null
        private set
    var expiringUsername2: String? = null
        private set
    var password2: String? = null
        private set

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    try {
                        turnServers = wellKnownCacheDelegate.getTurnUrls(ownedIdentity.server)
                        altTurnServers = wellKnownCacheDelegate.getAltTurnUrls(ownedIdentity.server)
                    } catch (_: NotCachedException) {
                        cancel(RFC_WELL_KNOWN_NOT_CACHED)
                        return
                    }

                    if (turnServers == null || turnServers!!.isEmpty()) {
                        cancel(RFC_SERVER_DOES_NOT_SUPPORT_CALLS)
                        return
                    }
                    val serverSessionToken: ByteArray? =
                        ServerSession.getToken(fetchManagerSession, ownedIdentity)

                    if (serverSessionToken == null) {
                        cancel(RFC_INVALID_SERVER_SESSION)
                        return
                    }


                    val serverMethod = GetTurnCredentialsServerMethod(
                        ownedIdentity,
                        serverSessionToken,
                        username1,
                        username2
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        fetchManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    )

                    when (returnStatus) {
                        ServerMethod.OK -> {
                            expiringUsername1 = serverMethod.expiringUsername1
                            password1 = serverMethod.password1
                            expiringUsername2 = serverMethod.expiringUsername2
                            password2 = serverMethod.password2
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

                        ServerMethod.PERMISSION_DENIED, ServerMethod.IDENTITY_IS_NOT_ACTIVE -> {
                            cancel(RFC_PERMISSION_DENIED)
                            return
                        }
                    }
                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                    fetchManagerSession.session.rollback()
                } finally {
                    if (finished) {
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
        const val RFC_INVALID_SERVER_SESSION: Int = 1
        const val RFC_WELL_KNOWN_NOT_CACHED: Int = 2
        const val RFC_PERMISSION_DENIED: Int = 3
        const val RFC_SERVER_DOES_NOT_SUPPORT_CALLS: Int = 4
    }
}

internal class GetTurnCredentialsServerMethod(
    private val identity: Identity,
    private val token: ByteArray,
    private val username1: String,
    private val username2: String
) : ServerMethod() {
    private val server: String

    var expiringUsername1: String? = null
        private set
    var password1: String? = null
        private set
    var expiringUsername2: String? = null
        private set
    var password2: String? = null
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
                Encoded.of(username1),
                Encoded.of(username2),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                expiringUsername1 = receivedData!![0]!!.decodeString()
                password1 = receivedData[1]!!.decodeString()
                expiringUsername2 = receivedData[2]!!.decodeString()
                password2 = receivedData[3]!!.decodeString()
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
        private const val SERVER_METHOD_PATH = "/getTurnCredentials"
    }
}