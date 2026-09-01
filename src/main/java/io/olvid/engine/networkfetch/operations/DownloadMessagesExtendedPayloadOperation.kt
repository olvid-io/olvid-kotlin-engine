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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class DownloadMessagesExtendedPayloadOperation(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    ownedIdentity: Identity,
    messageUid: UID?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(ownedIdentity.computeUniqueUid(), onFinishCallback, onCancelCallback) {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    @JvmField val ownedIdentity: Identity
    @JvmField val messageUid: UID?

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.ownedIdentity = ownedIdentity
        this.messageUid = messageUid
    }


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
                    if (serverSessionToken == null) {
                        cancel(RFC_INVALID_SERVER_SESSION)
                        return
                    }
                    val inboxMessage: InboxMessage? =
                        InboxMessage.get(fetchManagerSession, ownedIdentity, messageUid)
                    if (inboxMessage == null) {
                        cancel(RFC_MESSAGE_CANNOT_BE_FOUND)
                        return
                    }
                    val extendedPayloadKey = inboxMessage.extendedPayloadKey
                    if (extendedPayloadKey == null) {
                        cancel(RFC_EXTENDED_PAYLOAD_UNAVAILABLE_OR_INVALID)
                        return
                    }
                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = DownloadMessagesExtendedPayloadServerMethod(
                        ownedIdentity,
                        serverSessionToken,
                        messageUid!!
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
                            val messageExtendedPayload: ByteArray?
                            try {
                                val authEnc = Suite.getAuthEnc(extendedPayloadKey)!!
                                messageExtendedPayload = authEnc.decrypt(
                                    extendedPayloadKey,
                                    serverMethod.encryptedMessageExtendedPayload
                                )
                            } catch (_: Exception) {
                                cancel(RFC_EXTENDED_PAYLOAD_UNAVAILABLE_OR_INVALID)
                                return
                            }

                            fetchManagerSession.session.startTransaction()
                            inboxMessage.setExtendedPayload(messageExtendedPayload)
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

                        ServerMethod.EXTENDED_PAYLOAD_UNAVAILABLE -> {
                            cancel(RFC_EXTENDED_PAYLOAD_UNAVAILABLE_OR_INVALID)
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
        // possible reasons for cancel
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_INVALID_SERVER_SESSION: Int = 2
        const val RFC_IDENTITY_IS_INACTIVE: Int = 3
        const val RFC_EXTENDED_PAYLOAD_UNAVAILABLE_OR_INVALID: Int = 4
        const val RFC_MESSAGE_CANNOT_BE_FOUND: Int = 5
    }
}


internal class DownloadMessagesExtendedPayloadServerMethod(
    ownedIdentity: Identity,
    token: ByteArray,
    messageUid: UID
) : ServerMethod() {
    private val server: String
    private val ownedIdentity: Identity
    private val token: ByteArray
    private val messageUid: UID

    var encryptedMessageExtendedPayload: EncryptedBytes? = null
        private set

    init {
        this.server = ownedIdentity.server
        this.ownedIdentity = ownedIdentity
        this.token = token
        this.messageUid = messageUid
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
                Encoded.of(token),
                Encoded.of(messageUid)
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                encryptedMessageExtendedPayload = receivedData!![0]!!.decodeEncryptedData()
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
        private const val SERVER_METHOD_PATH = "/downloadMessageExtendedContent"
    }
}
