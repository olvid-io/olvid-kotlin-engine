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
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networksend.databases.MessageHeader
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class UploadMessageAndGetUidsOperation(
    private val sendManagerSessionFactory: SendManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val messageUid: UID
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
        val outboxMessage: OutboxMessage?
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                try {
                    outboxMessage =
                        OutboxMessage.get(sendManagerSession, ownedIdentity, messageUid)

                    if (outboxMessage == null) {
                        cancel(UploadMessageCompositeOperation.RFC_MESSAGE_NOT_FOUND_IN_DATABASE)
                        return
                    }
                    if (outboxMessage.uidFromServer != null) {
                        finished = true
                        return
                    }
                    val headers = outboxMessage.headers
                    val attachments = outboxMessage.attachments

                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = UploadMessageAndGetUidsServerMethod(
                        outboxMessage.server,
                        outboxMessage.encryptedContent,
                        outboxMessage.encryptedExtendedContent,
                        outboxMessage.isApplicationMessage,
                        outboxMessage.isVoipMessage,
                        headers ?: emptyArray(),
                        attachments?.filterNotNull()?.toTypedArray() ?: emptyArray()
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    // we need to block sending message for any inactive ownedIdentity, but, if the ownedIdentity was deleted, we should send the message
                    // this is required for the OwnedIdentityDeletion protocol, to inform your contacts
                    val sendMessage = sendManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                        sendManagerSession.session,
                        ownedIdentity
                    )
                            || !sendManagerSession.identityDelegate.isOwnedIdentity(
                        sendManagerSession.session,
                        ownedIdentity,
                        true
                    )
                    val returnStatus = serverMethod.execute(sendMessage)

                    sendManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            outboxMessage.setUidFromServer(
                                serverMethod.uidFromServer,
                                serverMethod.nonce,
                                serverMethod.timestampFromServer
                            )
                            val attachmentChunkUploadPrivateUrls =
                                serverMethod.getAttachmentChunkUploadPrivateUrls()
                            val nonNullAttachments = attachments?.filterNotNull() ?: emptyList()
                            for (i in nonNullAttachments.indices) {
                                nonNullAttachments[i].setChunkUploadPrivateUrls(
                                    attachmentChunkUploadPrivateUrls[i]
                                )
                            }
                            finished = true
                            return
                        }

                        ServerMethod.IDENTITY_IS_NOT_ACTIVE -> {
                            cancel(UploadMessageCompositeOperation.RFC_IDENTITY_IS_INACTIVE)
                            return
                        }

                        ServerMethod.OK_WITH_MALFORMED_SERVER_RESPONSE -> {
                            // unable to parse server response and get message Uid --> cancel all attachments and finish the operation
                            outboxMessage.setUidFromServer(
                                UID(ByteArray(UID.UID_LENGTH)),
                                ByteArray(0),
                                0
                            )
                            for (attachment in attachments ?: emptyArray()) {
                                attachment?.setCancelExternallyRequested()
                                attachment?.setCancelProcessed()
                            }
                            finished = true
                            return
                        }

                        ServerMethod.PAYLOAD_TOO_LARGE, ServerMethod.GENERAL_ERROR -> if (returnStatus == ServerMethod.PAYLOAD_TOO_LARGE
                            || System.currentTimeMillis() > outboxMessage.creationTimestamp + Constants.OUTBOX_MESSAGE_MAX_SEND_DELAY
                        ) {
                            // message is too large or too old --> we no longer try sending it
                            outboxMessage.setUidFromServer(
                                UID(ByteArray(UID.UID_LENGTH)),
                                ByteArray(0),
                                0
                            )
                            for (attachment in attachments ?: emptyArray()) {
                                attachment?.setCancelExternallyRequested()
                                attachment?.setCancelProcessed()
                            }
                            val userInfo = HashMap<String, Any>()
                            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED_UID_KEY] = outboxMessage.uid
                            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED_OWNED_IDENTITY_KEY] = outboxMessage.getOwnedIdentity()
                            sendManagerSession.notificationPostingDelegate?.postNotification(
                                UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED,
                                userInfo
                            )
                            finished = true
                        } else {
                            cancel(UploadMessageCompositeOperation.RFC_NETWORK_ERROR)
                        }

                        else -> if (returnStatus == ServerMethod.PAYLOAD_TOO_LARGE
                            || System.currentTimeMillis() > outboxMessage.creationTimestamp + Constants.OUTBOX_MESSAGE_MAX_SEND_DELAY
                        ) {
                            outboxMessage.setUidFromServer(
                                UID(ByteArray(UID.UID_LENGTH)),
                                ByteArray(0),
                                0
                            )
                            for (attachment in attachments ?: emptyArray()) {
                                attachment?.setCancelExternallyRequested()
                                attachment?.setCancelProcessed()
                            }
                            val userInfo = HashMap<String, Any>()
                            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED_UID_KEY] = outboxMessage.uid
                            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED_OWNED_IDENTITY_KEY] = outboxMessage.getOwnedIdentity()
                            sendManagerSession.notificationPostingDelegate?.postNotification(
                                UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED,
                                userInfo
                            )
                            finished = true
                        } else {
                            cancel(UploadMessageCompositeOperation.RFC_NETWORK_ERROR)
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
}


internal class UploadMessageAndGetUidsServerMethod(
    private val server: String?,
    private val encryptedMessage: EncryptedBytes,
    private val encryptedExtendedMessage: EncryptedBytes?,
    private val isApplicationMessage: Boolean,
    private val isVoipMessage: Boolean,
    private val headers: Array<MessageHeader?>,
    private val attachments: Array<OutboxAttachment>
) : ServerMethod() {
    var uidFromServer: UID? = null
        private set
    var nonce: ByteArray? = null
        private set
    var timestampFromServer: Long = 0
        private set
    private var attachmentChunkUploadPrivateUrls: Array<Array<String?>?>? = null


    fun getAttachmentChunkUploadPrivateUrls(): Array<Array<String?>?> {
        return attachmentChunkUploadPrivateUrls!!
    }

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        val encodedHeaders = arrayOfNulls<Encoded>(headers.size * 3)
        for (i in headers.indices) {
            encodedHeaders[3 * i] = Encoded.of(headers[i]!!.deviceUid)
            encodedHeaders[3 * i + 1] = Encoded.of(headers[i]!!.wrappedKey)
            encodedHeaders[3 * i + 2] = Encoded.of(headers[i]!!.getToIdentity())
        }
        val encodedAttachmentLengths = arrayOfNulls<Encoded>(attachments.size)
        val encodedChunkLengths = arrayOfNulls<Encoded>(attachments.size)
        for (i in attachments.indices) {
            encodedAttachmentLengths[i] = Encoded.of(attachments[i].ciphertextLength)
            encodedChunkLengths[i] = Encoded.of(attachments[i].ciphertextChunkLength.toLong())
        }
        @Suppress("UNCHECKED_CAST")
        if (encryptedExtendedMessage == null || encryptedExtendedMessage.length > Constants.MAX_MESSAGE_EXTENDED_CONTENT_LENGTH) {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(encodedHeaders as Array<Encoded>),
                    Encoded.of(encryptedMessage),
                    Encoded.of(isApplicationMessage),
                    Encoded.of(isVoipMessage),
                    Encoded.of(encodedAttachmentLengths as Array<Encoded>),
                    Encoded.of(encodedChunkLengths as Array<Encoded>)
                )
            ).bytes
        } else {
            @Suppress("UNCHECKED_CAST")
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(encodedHeaders as Array<Encoded>),
                    Encoded.of(encryptedMessage),
                    Encoded.of(encryptedExtendedMessage),
                    Encoded.of(isApplicationMessage),
                    Encoded.of(isVoipMessage),
                    Encoded.of(encodedAttachmentLengths as Array<Encoded>),
                    Encoded.of(encodedChunkLengths as Array<Encoded>)
                )
            ).bytes
        }
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                uidFromServer = receivedData!![0]!!.decodeUid()
                nonce = receivedData[1]!!.decodeBytes()
                timestampFromServer = receivedData[2]!!.decodeLong()
                val encodeds: Array<Encoded> = receivedData[3]!!.decodeList()
                if (encodeds.size != attachments.size) {
                    throw Exception()
                }
                attachmentChunkUploadPrivateUrls = arrayOfNulls<Array<String?>>(attachments.size)
                for (i in encodeds.indices) {
                    @Suppress("UNCHECKED_CAST")
                    attachmentChunkUploadPrivateUrls!![i] = encodeds[i].decodeStringArray() as Array<String?>
                }
            } catch (e: Exception) {
                Logger.x(e)
                returnStatus = OK_WITH_MALFORMED_SERVER_RESPONSE
            }
        }
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/uploadMessageAndGetUids"
    }
}
