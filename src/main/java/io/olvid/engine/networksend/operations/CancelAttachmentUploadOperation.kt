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
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class CancelAttachmentUploadOperation(
    private val sendManagerSessionFactory: SendManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val messageUid: UID,
    @JvmField val attachmentNumber: Int
) : Operation(
    IdentityAndUid.computeUniqueUid(
        ownedIdentity,
        messageUid
    ), null, null
) {
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
                    outboxMessage =
                        OutboxMessage.get(sendManagerSession, ownedIdentity, messageUid)
                    outboxAttachment = OutboxAttachment.get(
                        sendManagerSession,
                        ownedIdentity,
                        messageUid,
                        attachmentNumber
                    )

                    if (outboxMessage == null || outboxAttachment == null) {
                        cancel(CancelAttachmentUploadCompositeOperation.RFC_ATTACHMENT_NOT_FOUND_IN_DATABASE)
                        return
                    }
                    if (outboxMessage.uidFromServer == null) {
                        finished = true
                        return
                    }

                    if (outboxAttachment.isAcknowledged) {
                        finished = true
                        return
                    }

                    if (cancelWasRequested()) {
                        return
                    }

                    val uidFromServer = outboxMessage.uidFromServer!!
                    val serverMethod = CancelAttachmentUploadServerMethod(
                        outboxMessage.server,
                        uidFromServer,
                        outboxMessage.nonce!!,
                        attachmentNumber
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
                        ServerMethod.INVALID_NONCE -> {
                            Logger.i("Received INVALID_NONCE in CancelAttachmentUploadOperation")
                            outboxAttachment.setCancelProcessed()
                            finished = true
                            return
                        }

                        ServerMethod.OK -> {
                            outboxAttachment.setCancelProcessed()
                            finished = true
                            return
                        }

                        ServerMethod.IDENTITY_IS_NOT_ACTIVE -> {
                            cancel(CancelAttachmentUploadCompositeOperation.RFC_IDENTITY_IS_INACTIVE)
                            return
                        }

                        else -> cancel(CancelAttachmentUploadCompositeOperation.RFC_NETWORK_ERROR)
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
}


internal class CancelAttachmentUploadServerMethod(
    private val server: String?,
    private val uidFromServer: UID,
    private val nonce: ByteArray,
    private val attachmentNumber: Int
) : ServerMethod() {
    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(uidFromServer),
                Encoded.of(attachmentNumber.toLong()),
                Encoded.of(nonce),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        // nothing to parse here
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/cancelAttachmentUpload"
    }
}
