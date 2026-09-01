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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networksend.databases.MessageHeader
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class BatchUploadMessagesOperation(
    private val sendManagerSessionFactory: SendManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    private val server: String?,
    private val messageIdentitiesAndUids: Array<IdentityAndUid>
) : Operation() {
    @JvmField val tooManyHeadersUnsentMessageUids: MutableList<IdentityAndUid?>
    @JvmField val identityInactiveMessageUids: MutableList<IdentityAndUid?>

    init {
        this.tooManyHeadersUnsentMessageUids = ArrayList<IdentityAndUid?>()
        this.identityInactiveMessageUids = ArrayList<IdentityAndUid?>()
    }

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                try {
                    val outboxMessageAndHeaders: MutableList<OutboxMessageAndHeaders> =
                        ArrayList<OutboxMessageAndHeaders>()
                    var totalHeaders = 0

                    Logger.d("BatchUploadMessagesOperation uploading a batch of " + messageIdentitiesAndUids.size)

                    val messageUidsByIdentity = HashMap<Identity?, MutableList<UID?>?>()
                    for (identityAndUid in messageIdentitiesAndUids) {
                        var list = messageUidsByIdentity.get(identityAndUid.identity)
                        if (list == null) {
                            list = ArrayList<UID?>()
                            messageUidsByIdentity.put(identityAndUid.identity, list)
                        }
                        list.add(identityAndUid.uid)
                    }

                    for (entry in messageUidsByIdentity.entries) {
                        val ownedIdentity: Identity = entry.key!!
                        val messageUids: MutableList<UID?> = entry.value ?: ArrayList()
                        // we need to block sending message for any inactive ownedIdentity, but, if the ownedIdentity was deleted, we should send the message
                        // this is required for the OwnedIdentityDeletion protocol, to inform your contacts
                        if (!sendManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                                sendManagerSession.session,
                                ownedIdentity
                            )
                            && sendManagerSession.identityDelegate.isOwnedIdentity(
                                sendManagerSession.session,
                                ownedIdentity,
                                true
                            )
                        ) {
                            for (messageUid in messageUids) {
                                identityInactiveMessageUids.add(
                                    IdentityAndUid(
                                        ownedIdentity,
                                        messageUid!!
                                    )
                                )
                            }
                        } else {
                            val outboxMessages: Array<OutboxMessage?>? =
                                OutboxMessage.getManyWithoutUidFromServer(
                                    sendManagerSession,
                                    ownedIdentity,
                                    server,
                                    messageUids.toTypedArray()
                                )
                            for (outboxMessage in outboxMessages ?: emptyArray()) {
                                if (outboxMessage == null) continue
                                if (totalHeaders > Constants.MAX_UPLOAD_MESSAGE_BATCH_HEADER_COUNT) {
                                    tooManyHeadersUnsentMessageUids.add(
                                        IdentityAndUid(
                                            outboxMessage.getOwnedIdentity(),
                                            outboxMessage.uid
                                        )
                                    )
                                } else {
                                    val headers = outboxMessage.headers ?: emptyArray()
                                    outboxMessageAndHeaders.add(
                                        OutboxMessageAndHeaders(
                                            outboxMessage,
                                            headers
                                        )
                                    )
                                    totalHeaders += headers.size
                                }
                            }
                        }
                    }

                    Logger.d("Total header count for this batch: " + totalHeaders)

                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = BatchUploadMessagesServerMethod(
                        server,
                        outboxMessageAndHeaders.toTypedArray<OutboxMessageAndHeaders>()
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(true)

                    sendManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            for (outboxMessageAndHeader in serverMethod.outboxMessageAndHeaders) {
                                outboxMessageAndHeader.outboxMessage.setUidFromServer(
                                    outboxMessageAndHeader.uidFromServer,
                                    outboxMessageAndHeader.nonce,
                                    outboxMessageAndHeader.timestampFromServer
                                )
                            }

                            finished = true
                            return
                        }

                        ServerMethod.OK_WITH_MALFORMED_SERVER_RESPONSE -> {
                            // unable to parse server response and get message Uids --> finish the operation
                            for (outboxMessageAndHeader in outboxMessageAndHeaders) {
                                outboxMessageAndHeader.outboxMessage.setUidFromServer(
                                    UID(
                                        ByteArray(
                                            UID.UID_LENGTH
                                        )
                                    ), ByteArray(0), 0
                                )
                            }
                            finished = true
                            return
                        }

                        ServerMethod.PAYLOAD_TOO_LARGE -> {
                            cancel(BatchUploadMessagesCompositeOperation.RFC_BATCH_TOO_LARGE)
                        }

                        ServerMethod.GENERAL_ERROR -> cancel(BatchUploadMessagesCompositeOperation.RFC_NETWORK_ERROR)
                        else -> cancel(BatchUploadMessagesCompositeOperation.RFC_NETWORK_ERROR)
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

internal class OutboxMessageAndHeaders(
    @JvmField val outboxMessage: OutboxMessage,
    @JvmField val headers: Array<MessageHeader?>
) {
    @JvmField var uidFromServer: UID? = null
    @JvmField var nonce: ByteArray? = null
    @JvmField var timestampFromServer: Long = 0
}

internal class BatchUploadMessagesServerMethod(
    private val server: String?,
    @JvmField val outboxMessageAndHeaders: Array<OutboxMessageAndHeaders>
) : ServerMethod() {
    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        val encodeds = arrayOfNulls<Encoded>(outboxMessageAndHeaders.size)
        for (i in outboxMessageAndHeaders.indices) {
            val headers = outboxMessageAndHeaders[i].headers

            val encodedHeaders = arrayOfNulls<Encoded>(headers.size * 3)
            for (j in headers.indices) {
                encodedHeaders[3 * j] = Encoded.of(headers[j]!!.deviceUid)
                encodedHeaders[3 * j + 1] = Encoded.of(headers[j]!!.wrappedKey)
                encodedHeaders[3 * j + 2] = Encoded.of(headers[j]!!.getToIdentity())
            }
            encodeds[i] = Encoded.of(
                arrayOf<Encoded>(
                    @Suppress("UNCHECKED_CAST") Encoded.of(encodedHeaders as Array<Encoded>),
                    Encoded.of(outboxMessageAndHeaders[i].outboxMessage.encryptedContent),
                    Encoded.of(outboxMessageAndHeaders[i].outboxMessage.isApplicationMessage),
                    Encoded.of(outboxMessageAndHeaders[i].outboxMessage.isVoipMessage)
                )
            )
        }
        @Suppress("UNCHECKED_CAST")
        return Encoded.of(encodeds as Array<Encoded>).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            if (receivedData!!.size != outboxMessageAndHeaders.size) {
                returnStatus = OK_WITH_MALFORMED_SERVER_RESPONSE
            } else {
                try {
                    for (i in outboxMessageAndHeaders.indices) {
                        val encodeds: Array<Encoded> = receivedData[i]!!.decodeList()
                        outboxMessageAndHeaders[i].uidFromServer = encodeds[0].decodeUid()
                        outboxMessageAndHeaders[i].nonce = encodeds[1].decodeBytes()
                        outboxMessageAndHeaders[i].timestampFromServer = encodeds[2].decodeLong()
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                    returnStatus = OK_WITH_MALFORMED_SERVER_RESPONSE
                }
            }
        }
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/batchUploadMessages"
    }
}
