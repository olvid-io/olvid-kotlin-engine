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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory


internal class GetTokenOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    onFinishCallback: OnFinishCallback?
) : Operation(
    ownedIdentity.computeUniqueUid(), onFinishCallback, null
) {
    var apiKeyStatus: ServerSession.ApiKeyStatus? = null
        private set
    var permissions: MutableList<ServerSession.Permission?>? = null
        private set
    var apiKeyExpirationTimestamp: Long = 0
        private set

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        val serverSession: ServerSession?
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    serverSession = ServerSession.get(fetchManagerSession, ownedIdentity)

                    if (serverSession == null) {
                        cancel(CreateServerSessionCompositeOperation.RFC_SESSION_CANNOT_BE_FOUND)
                        return
                    }
                    val serverSessionNonce = serverSession.nonce
                    if (serverSessionNonce == null) {
                        cancel(CreateServerSessionCompositeOperation.RFC_SESSION_DOES_NOT_CONTAIN_A_NONCE)
                        return
                    }
                    val serverSessionResponse = serverSession.response
                    if (serverSessionResponse == null) {
                        cancel(CreateServerSessionCompositeOperation.RFC_SESSION_DOES_NOT_CONTAIN_A_RESPONSE)
                        return
                    }
                    if (serverSession.token != null) {
                        finished = true
                        return
                    }
                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = GetTokenServerMethod(
                        ownedIdentity,
                        serverSessionResponse,
                        serverSessionNonce
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
                            serverSession.setTokenAndPermissions(
                                serverMethod.token,
                                serverMethod.apiKeyStatus,
                                serverMethod.permissions,
                                serverMethod.apiKeyExpiration
                            )
                            apiKeyStatus = serverSession.getApiKeyStatus()
                            permissions = serverSession.getPermissions()
                            apiKeyExpirationTimestamp = serverSession.apiKeyExpirationTimestamp
                            finished = true
                            return
                        }

                        ServerMethod.INVALID_SESSION -> {
                            serverSession.delete()
                            fetchManagerSession.session.commit()
                            cancel(CreateServerSessionCompositeOperation.RFC_INVALID_SESSION)
                            return
                        }

                        else -> {
                            cancel(CreateServerSessionCompositeOperation.RFC_NETWORK_ERROR)
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
}

internal class GetTokenServerMethod(
    private val identity: Identity,
    private val response: ByteArray,
    private val nonce: ByteArray
) : ServerMethod() {
    private val server: String

    var token: ByteArray? = null
        private set
    var apiKeyStatus: Int = -1
        private set
    var permissions: Long = 0
        private set
    var apiKeyExpiration: Long = 0
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
                Encoded.of(response),
                Encoded.of(nonce)
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                val token = receivedData!![0]!!.decodeBytes()
                val serverNonce = receivedData[1]!!.decodeBytes()
                if (!nonce.contentEquals(serverNonce) ||
                    (token.size != Constants.SERVER_SESSION_TOKEN_LENGTH)
                ) {
                    returnStatus = GENERAL_ERROR
                    return
                }
                this.token = token
                this.apiKeyStatus = receivedData[2]!!.decodeLong().toInt()
                this.permissions = receivedData[3]!!.decodeLong()
                this.apiKeyExpiration = receivedData[4]!!.decodeLong()
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }

    override fun isActiveIdentityRequired(): Boolean {
        return false
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/getToken"
    }
}