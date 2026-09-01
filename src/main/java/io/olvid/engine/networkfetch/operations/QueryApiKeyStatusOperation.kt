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
import io.olvid.engine.networkfetch.databases.ServerSession
import java.util.UUID
import javax.net.ssl.SSLSocketFactory


class QueryApiKeyStatusOperation(
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val apiKey: UUID?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(null, onFinishCallback, onCancelCallback) {
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
        val serverMethod = QueryApiKeyStatusServerMethod(ownedIdentity, apiKey)
        serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

        val returnStatus = serverMethod.execute(true)

        if (returnStatus == ServerMethod.OK) {
            apiKeyStatus = ServerSession.deserializeApiKeyStatus(
                serverMethod.apiKeyStatus
            )
            permissions = ServerSession.deserializePermissions(
                serverMethod.permissions
            )
            apiKeyExpirationTimestamp = serverMethod.apiKeyExpiration
            setFinished()
        } else {
            cancel(null)
            processCancel()
        }
    }
}

internal class QueryApiKeyStatusServerMethod(
    private val ownedIdentity: Identity,
    private val apiKey: UUID?
) : ServerMethod() {
    private val server: String

    var apiKeyStatus: Int = -1
        private set
    var permissions: Long = 0
        private set
    var apiKeyExpiration: Long = 0
        private set

    init {
        this.server = ownedIdentity.server
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
                Encoded.of(ownedIdentity),
                Encoded.of(apiKey),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                this.apiKeyStatus = receivedData!![0]!!.decodeLong().toInt()
                this.permissions = receivedData[1]!!.decodeLong()
                this.apiKeyExpiration = receivedData[2]!!.decodeLong()
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
        private const val SERVER_METHOD_PATH = "/queryApiKeyStatus"
    }
}