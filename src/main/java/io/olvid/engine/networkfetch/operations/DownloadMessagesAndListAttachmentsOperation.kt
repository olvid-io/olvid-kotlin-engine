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
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PriorityOperation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.InboxAttachment
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class DownloadMessagesAndListAttachmentsOperation(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    ownedIdentity: Identity,
    deviceUid: UID,
    listStartTimestamp: Long,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : PriorityOperation(
    computeUniqueUid(ownedIdentity, listStartTimestamp), onFinishCallback, onCancelCallback
) {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    @JvmField val ownedIdentity: Identity
    @JvmField val deviceUid: UID
    private val listStartTimestamp: Long
    var timestampOfLastMessageBeforeTruncation: Long? = null
        private set
    var downloadTimestamp: Long = 0
        private set

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride
        this.ownedIdentity = ownedIdentity
        this.deviceUid = deviceUid
        this.listStartTimestamp = listStartTimestamp
    }

    override fun getPriority(): Long {
        return (if (listStartTimestamp == 0L) 10 else 5).toLong()
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
                    if (cancelWasRequested()) {
                        return
                    }

                    // if this is the first listing for this identity, notify that a not-user-initiated listing is in progress
                    synchronized(notifiedIdentities) {
                        if (!notifiedIdentities.contains(ownedIdentity)) {
                            notifiedIdentities.add(ownedIdentity)

                            val userInfo = HashMap<String, Any>()
                            userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED_OWNED_IDENTITY_KEY] = ownedIdentity
                            userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED_USER_INITIATED_KEY] = false
                            fetchManagerSession.notificationPostingDelegate?.postNotification(
                                DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED,
                                userInfo
                            )
                        }
                    }

                    val serverMethod = DownloadMessagesAndListAttachmentsServerMethod(
                        ownedIdentity,
                        serverSessionToken,
                        deviceUid,
                        listStartTimestamp
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        fetchManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    )
                    val localDownloadTimestamp = System.currentTimeMillis()

                    when (returnStatus) {
                        ServerMethod.OK, ServerMethod.LISTING_TRUNCATED -> {
                            downloadTimestamp = serverMethod.downloadTimestamp
                            val messageAndAttachmentLengthsArray =
                                serverMethod.messageAndAttachmentLengthsArray
                            var count = 0

                            fetchManagerSession.session.startTransaction()

                            for (messageAndAttachmentLengths in messageAndAttachmentLengthsArray) {
                                if (!InboxMessage.exists(
                                        fetchManagerSession,
                                        ownedIdentity,
                                        messageAndAttachmentLengths.messageUid
                                    )
                                ) {
                                    val message: InboxMessage? = InboxMessage.create(
                                        fetchManagerSession,
                                        ownedIdentity,
                                        messageAndAttachmentLengths.messageUid,
                                        messageAndAttachmentLengths.messageContent,
                                        messageAndAttachmentLengths.wrappedKey,
                                        messageAndAttachmentLengths.serverTimestamp,
                                        downloadTimestamp,
                                        localDownloadTimestamp,
                                        messageAndAttachmentLengths.hasExtendedContent
                                    )
                                    if (message == null) {
                                        continue
                                    }
                                    count++

                                    var i = 0
                                    while (i < messageAndAttachmentLengths.attachmentLengths.size) {
                                        val attachment: InboxAttachment? =
                                            InboxAttachment.get(
                                                fetchManagerSession,
                                                ownedIdentity,
                                                messageAndAttachmentLengths.messageUid,
                                                i
                                            )
                                        if (attachment == null) {
                                            if (messageAndAttachmentLengths.uploadCancelled[i]) {
                                                Logger.i("One attachment had its upload cancelled.")
                                                InboxAttachment.createUploadCancelled(
                                                    fetchManagerSession,
                                                    ownedIdentity,
                                                    messageAndAttachmentLengths.messageUid,
                                                    i,
                                                    messageAndAttachmentLengths.attachmentLengths[i],
                                                    messageAndAttachmentLengths.chunkLengths[i]
                                                )
                                            } else {
                                                InboxAttachment.create(
                                                    fetchManagerSession,
                                                    ownedIdentity,
                                                    messageAndAttachmentLengths.messageUid,
                                                    i,
                                                    messageAndAttachmentLengths.attachmentLengths[i],
                                                    messageAndAttachmentLengths.chunkLengths[i],
                                                    messageAndAttachmentLengths.chunkDownloadPrivateUrls[i]
                                                )
                                            }
                                        }
                                        i++
                                    }
                                } else {
                                    // we relisted a message --> mark it as listed
                                    fetchManagerSession.markAsListedAndDeleteOnServerListener?.messageCanBeMarkedAsListedOnServer(
                                        ownedIdentity,
                                        messageAndAttachmentLengths.messageUid,
                                        true // we are not sure if this message has attachments (we do not want the additional DB call), so let's assume it has so it is marked as listed on server and not deleted
                                    )
                                }
                            }
                            Logger.d("DownloadMessagesAndListAttachmentsOperation found " + messageAndAttachmentLengthsArray.size + " messages (" + count + " new) on the server.")
                            timestampOfLastMessageBeforeTruncation =
                                if (returnStatus == ServerMethod.LISTING_TRUNCATED) messageAndAttachmentLengthsArray[messageAndAttachmentLengthsArray.size - 1].serverTimestamp else null
                            if (timestampOfLastMessageBeforeTruncation == null) {
                                // if the listing was not truncated, we can delete expired PreKeys
                                fetchManagerSession.identityDelegate.expireCurrentDeviceOwnedPreKeys(
                                    fetchManagerSession.session,
                                    ownedIdentity,
                                    downloadTimestamp
                                )
                            }

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

                        ServerMethod.DEVICE_IS_NOT_REGISTERED -> {
                            cancel(RFC_DEVICE_NOT_REGISTERED)
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
        const val RFC_IDENTITY_IS_INACTIVE: Int = 4
        const val RFC_DEVICE_NOT_REGISTERED: Int = 5

        private val notifiedIdentities: MutableSet<Identity?> = HashSet<Identity?>()

        private fun computeUniqueUid(ownedIdentity: Identity, listStartTimestamp: Long): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            val input = ByteArray(ownedIdentity.getBytes().size + 1)
            System.arraycopy(ownedIdentity.getBytes(), 0, input, 0, ownedIdentity.getBytes().size)
            input[input.size - 1] = (if (listStartTimestamp == 0L) 0x00 else 0x01).toByte()
            return UID(sha256.digest(input))
        }
    }
}


internal class DownloadMessagesAndListAttachmentsServerMethod(
    ownedIdentity: Identity,
    token: ByteArray,
    deviceUid: UID,
    listStartTimestamp: Long
) : ServerMethod() {
    private val server: String
    private val ownedIdentity: Identity
    private val token: ByteArray
    private val deviceUid: UID
    private val listStartTimestamp: Long

    var messageAndAttachmentLengthsArray: Array<MessageAndAttachmentLengths> = emptyArray()
        private set
    var downloadTimestamp: Long = 0
        private set

    init {
        this.server = ownedIdentity.server
        this.ownedIdentity = ownedIdentity
        this.token = token
        this.deviceUid = deviceUid
        this.listStartTimestamp = listStartTimestamp
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf(
                Encoded.of(ownedIdentity),
                Encoded.of(token),
                Encoded.of(deviceUid),
                Encoded.of(listStartTimestamp)
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK
            || returnStatus == LISTING_TRUNCATED
        ) {
            try {
                downloadTimestamp = receivedData!![0]!!.decodeLong()
                val list: MutableList<MessageAndAttachmentLengths> =
                    ArrayList<MessageAndAttachmentLengths>()
                for (i in 0..<receivedData.size - 1) {
                    val parts: Array<Encoded> = receivedData[i + 1]!!.decodeList()
                    val attachmentCount = parts.size - 5
                    val messageAndAttachmentLengths = MessageAndAttachmentLengths(
                        parts[0].decodeUid(),
                        parts[1].decodeLong(),
                        parts[2].decodeEncryptedData(),
                        parts[3].decodeEncryptedData(),
                        parts[4].decodeBoolean(),
                        attachmentCount
                    )
                    for (j in 0..<attachmentCount) {
                        val attachmentParts: Array<Encoded> = parts[5 + j].decodeList()
                        val attachmentNumber = attachmentParts[0].decodeLong().toInt()
                        val attachmentStatus = attachmentParts[1].decodeBytes()[0]

                        if (attachmentStatus == UPLOAD_CANCELLED) {
                            val attachmentLength = attachmentParts[2].decodeLong()
                            val chunkLength = attachmentParts[3].decodeLong().toInt()
                            messageAndAttachmentLengths.uploadCancelled[attachmentNumber] = true
                            messageAndAttachmentLengths.attachmentLengths[attachmentNumber] =
                                attachmentLength
                            messageAndAttachmentLengths.chunkLengths[attachmentNumber] = chunkLength
                            messageAndAttachmentLengths.chunkDownloadPrivateUrls[attachmentNumber] =
                                null
                        } else {
                            val attachmentLength = attachmentParts[2].decodeLong()
                            val chunkLength = attachmentParts[3].decodeLong().toInt()
                            @Suppress("UNCHECKED_CAST")
                            val privateUrls: Array<String?> = attachmentParts[4].decodeStringArray() as Array<String?>
                            messageAndAttachmentLengths.uploadCancelled[attachmentNumber] = false
                            messageAndAttachmentLengths.attachmentLengths[attachmentNumber] =
                                attachmentLength
                            messageAndAttachmentLengths.chunkLengths[attachmentNumber] = chunkLength
                            if (chunkLength == 0) {
                                continue
                            }
                            if (privateUrls.size == ((attachmentLength - 1) / chunkLength).toInt() + 1) {
                                messageAndAttachmentLengths.chunkDownloadPrivateUrls[attachmentNumber] =
                                    privateUrls
                            } else {
                                messageAndAttachmentLengths.chunkDownloadPrivateUrls[attachmentNumber] =
                                    null
                            }
                        }
                    }
                    list.add(messageAndAttachmentLengths)
                }
                messageAndAttachmentLengthsArray = list.toTypedArray<MessageAndAttachmentLengths>()
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            } catch (e: ArrayIndexOutOfBoundsException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    internal class MessageAndAttachmentLengths(
        messageUid: UID?,
        serverTimestamp: Long,
        wrappedKey: EncryptedBytes?,
        messageContent: EncryptedBytes?,
        hasExtendedContent: Boolean,
        attachmentCount: Int
    ) {
        @JvmField val messageUid: UID?
        @JvmField val serverTimestamp: Long
        @JvmField val wrappedKey: EncryptedBytes?
        @JvmField val messageContent: EncryptedBytes?
        @JvmField val hasExtendedContent: Boolean
        @JvmField val uploadCancelled: BooleanArray
        @JvmField val attachmentLengths: LongArray
        @JvmField val chunkLengths: IntArray

        // chunkDownloadPrivateUrls[i] == null if we received the wrong number of chunkUrl --> we need to refresh them from server
        @JvmField val chunkDownloadPrivateUrls: Array<Array<String?>?>

        init {
            this.messageUid = messageUid
            this.serverTimestamp = serverTimestamp
            this.wrappedKey = wrappedKey
            this.messageContent = messageContent
            this.hasExtendedContent = hasExtendedContent
            this.uploadCancelled = BooleanArray(attachmentCount)
            this.attachmentLengths = LongArray(attachmentCount)
            this.chunkLengths = IntArray(attachmentCount)
            this.chunkDownloadPrivateUrls = arrayOfNulls<Array<String?>>(attachmentCount)
        }
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/downloadMessagesAndListAttachments"
    }
}
