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
package io.olvid.engine.networksend.operations

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class RefreshOutboxAttachmentSignedUrlOperation(
    sendManagerSessionFactory: SendManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    ownedIdentity: Identity,
    messageUid: UID,
    attachmentNumber: Int,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    OutboxAttachment.computeUniqueUid(
        ownedIdentity,
        messageUid,
        attachmentNumber
    ), onFinishCallback, onCancelCallback
) {
    private val sendManagerSessionFactory: SendManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    @JvmField val ownedIdentity: Identity
    @JvmField val messageUid: UID
    @JvmField val attachmentNumber: Int

    init {
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.ownedIdentity = ownedIdentity
        this.messageUid = messageUid
        this.attachmentNumber = attachmentNumber
    }

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        val outboxAttachment: OutboxAttachment?
        val outboxMessage: OutboxMessage?
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                try {
                    outboxAttachment = OutboxAttachment.get(
                        sendManagerSession,
                        ownedIdentity,
                        messageUid,
                        attachmentNumber
                    )

                    if (outboxAttachment == null) {
                        cancel(RFC_ATTACHMENT_NOT_FOUND)
                        return
                    }
                    outboxMessage = OutboxMessage.get(
                        sendManagerSession,
                        outboxAttachment.getOwnedIdentity(),
                        outboxAttachment.messageUid
                    )
                    if (outboxMessage == null || outboxMessage.uidFromServer == null) {
                        cancel(RFC_ATTACHMENT_NOT_FOUND)
                        return
                    }

                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = RefreshOutboxAttachmentSignedUrlServerMethod(
                        outboxMessage.server,
                        outboxMessage.uidFromServer!!,
                        outboxMessage.nonce!!,
                        attachmentNumber,
                        outboxAttachment.numberOfChunks
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        sendManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                            sendManagerSession.session,
                            ownedIdentity
                        )
                    )

                    sendManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            outboxAttachment.setChunkUploadPrivateUrls(serverMethod.signedUrls)
                            finished = true
                            return
                        }

                        ServerMethod.INVALID_NONCE -> {
                            cancel(RFC_INVALID_NONCE)
                            return
                        }

                        ServerMethod.DELETED_FROM_SERVER -> {
                            cancel(RFC_DELETED_FROM_SERVER)
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
                    sendManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        sendManagerSession.session.commit()
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
        const val RFC_ATTACHMENT_NOT_FOUND: Int = 2
        const val RFC_DELETED_FROM_SERVER: Int = 3
        const val RFC_IDENTITY_IS_INACTIVE: Int = 4
        const val RFC_INVALID_NONCE: Int = 5
    }
}

internal class RefreshOutboxAttachmentSignedUrlServerMethod(
    server: String?,
    messageUidFromServer: UID,
    nonce: ByteArray,
    attachmentNumber: Int,
    expectedChunkCount: Int
) : ServerMethod() {
    private val server: String?
    private val messageUidFromServer: UID
    private val nonce: ByteArray
    private val attachmentNumber: Int
    private val expectedChunkCount: Int

    var signedUrls: Array<String?>? = null
        private set

    init {
        this.server = server
        this.messageUidFromServer = messageUidFromServer
        this.nonce = nonce
        this.attachmentNumber = attachmentNumber
        this.expectedChunkCount = expectedChunkCount
    }

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(messageUidFromServer),
                Encoded.of(attachmentNumber.toLong()),
                Encoded.of(nonce),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                val signedUrls: Array<String> = receivedData!![0]!!.decodeStringArray()
                if (signedUrls.size != expectedChunkCount) {
                    throw DecodingException("Attachment chunk count mismatch")
                }
                @Suppress("UNCHECKED_CAST")
                this.signedUrls = signedUrls as Array<String?>
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
        private const val SERVER_METHOD_PATH = "/uploadAttachment"
    }
}
