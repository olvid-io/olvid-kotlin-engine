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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.EtaEstimator
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PriorityOperation
import io.olvid.engine.datatypes.ServerMethodForS3
import io.olvid.engine.datatypes.ServerMethodForS3.ServerMethodForS3ProgressListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.encoder.Encoded.Companion.encodeChunk
import io.olvid.engine.networksend.coordinators.SendAttachmentCoordinator
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.io.FileNotFoundException
import java.lang.ref.WeakReference
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class UploadAttachmentOperation(
    private val sendManagerSessionFactory: SendManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val messageUid: UID,
    @JvmField val attachmentNumber: Int, // will be updated as the attachment is downloaded, so cannot be final
    private var priority: Long,
    coordinator: SendAttachmentCoordinator?
) : PriorityOperation(
    OutboxAttachment.computeUniqueUid(
        ownedIdentity,
        messageUid,
        attachmentNumber
    ), null, null
) {
    private val coordinatorWeakReference: WeakReference<SendAttachmentCoordinator?>

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    private var outboxAttachment: OutboxAttachment? = null

    init {
        this.coordinatorWeakReference = WeakReference<SendAttachmentCoordinator?>(coordinator)
    }

    override fun doExecute() {
        var finished = false
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                try {
                    val outboxMessage: OutboxMessage?
                    try {
                        outboxAttachment = OutboxAttachment.get(
                            sendManagerSession,
                            ownedIdentity,
                            messageUid,
                            attachmentNumber
                        )
                        outboxMessage = OutboxMessage.get(
                            sendManagerSession,
                            ownedIdentity,
                            messageUid
                        )
                    } catch (_: SQLException) {
                        return
                    }

                    if (outboxAttachment == null) {
                        cancel(UploadAttachmentCompositeOperation.RFC_ATTACHMENT_NOT_FOUND_IN_DATABASE)
                        return
                    }
                    if (outboxMessage == null || outboxMessage.uidFromServer == null) {
                        cancel(UploadAttachmentCompositeOperation.RFC_MESSAGE_HAS_NO_UID_FROM_SERVER)
                        return
                    }
                    if (outboxAttachment!!.isAcknowledged || outboxAttachment!!.isCancelExternallyRequested) {
                        finished = true
                        return
                    }


                    try {
                        sendManagerSession.fileIo.file(
                            sendManagerSession.engineBaseDirectory,
                            outboxAttachment!!.url!!
                        ).openInput().use { f ->
                            val cleartextChunkLength = outboxAttachment!!.cleartextChunkLength
                            val buffer = ByteArray(cleartextChunkLength)

                            val cleartextOffset = outboxAttachment!!.getAcknowledgedChunkCount()
                                .toLong() * cleartextChunkLength
                            f.seek(cleartextOffset)

                            val authEnc = Suite.getAuthEnc(outboxAttachment!!.key)!!
                            val prng = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)

                            val etaEstimator = EtaEstimator(
                                outboxAttachment!!.ciphertextChunkLength
                                    .toLong() * outboxAttachment!!.getAcknowledgedChunkCount()
                                    .toLong(), outboxAttachment!!.ciphertextLength
                            )

                            while (outboxAttachment != null && !outboxAttachment!!.isAcknowledged) {
                                if (cancelWasRequested()) {
                                    return
                                }

                                if (outboxAttachment!!.isCancelExternallyRequested) {
                                    finished = true
                                    return
                                }
                                if (outboxAttachment!!.getChunkUploadPrivateUrls().size == 0) {
                                    cancel(UploadAttachmentCompositeOperation.RFC_INVALID_SIGNED_URL)
                                    return
                                }

                                var bufferFullness = 0
                                while (bufferFullness < buffer.size) {
                                    val count =
                                        f.read(buffer, bufferFullness, buffer.size - bufferFullness)
                                    if (count < 0) {
                                        break
                                    }
                                    bufferFullness += count
                                }
                                val chunkNumber = outboxAttachment!!.getAcknowledgedChunkCount()

                                val serverMethod = UploadAttachmentServerMethodForS3(
                                    outboxAttachment!!.getChunkUploadPrivateUrls()[chunkNumber],
                                    authEnc.encrypt(
                                        outboxAttachment!!.key,
                                        encodeChunk(chunkNumber, buffer, bufferFullness),
                                        prng
                                    )
                                )
                                serverMethod.setSslSocketFactory(
                                    sslSocketFactory,
                                    userAgentOverride
                                )

                                serverMethod.setProgressListener(
                                    150,
                                    object : ServerMethodForS3ProgressListener {
                                        val userInfo: HashMap<String, Any> = HashMap<String, Any>().also { map ->
                                            map[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_OWNED_IDENTITY_KEY] = ownedIdentity
                                            map[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_MESSAGE_UID_KEY] = messageUid
                                            map[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY] = attachmentNumber
                                        }
                                        val totalLength: Long = outboxAttachment!!.ciphertextLength
                                        val chunkLength: Long = outboxAttachment!!.ciphertextChunkLength.toLong()

                                        override fun onProgress(byteCount: Long) {
                                            val progress =
                                                (outboxAttachment!!.getAcknowledgedChunkCount() * chunkLength + byteCount).toFloat() / totalLength
                                            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_PROGRESS_KEY] = progress
                                            etaEstimator.update(outboxAttachment!!.getAcknowledgedChunkCount() * chunkLength + byteCount)
                                            val speedAndEta = etaEstimator.speedAndEta
                                            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_SPEED_BPS_KEY] = speedAndEta.speedBps
                                            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_ETA_SECONDS_KEY] = speedAndEta.etaSeconds
                                            sendManagerSession.notificationPostingDelegate?.postNotification(
                                                UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS,
                                                userInfo
                                            )
                                        }
                                    })
                                val returnStatus = serverMethod.execute(
                                    sendManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                                        sendManagerSession.session,
                                        ownedIdentity
                                    )
                                )

                                when (returnStatus) {
                                    ServerMethodForS3.OK -> {
                                        val coordinator = coordinatorWeakReference.get()
                                        if (coordinator != null) {
                                            coordinator.resetFailedAttemptCount(
                                                ownedIdentity,
                                                messageUid,
                                                attachmentNumber
                                            )
                                        }
                                        outboxAttachment!!.setAcknowledgedChunkCount(chunkNumber + 1)
                                        sendManagerSession.session.commit()
                                    }

                                    ServerMethodForS3.GENERAL_ERROR -> {
                                        cancel(null)
                                        return
                                    }

                                    ServerMethodForS3.INVALID_SIGNED_URL -> {
                                        cancel(UploadAttachmentCompositeOperation.RFC_INVALID_SIGNED_URL)
                                        return
                                    }

                                    ServerMethodForS3.IDENTITY_IS_NOT_ACTIVE -> {
                                        cancel(UploadAttachmentCompositeOperation.RFC_IDENTITY_IS_INACTIVE)
                                        return
                                    }

                                    else -> {
                                        cancel(UploadAttachmentCompositeOperation.RFC_NETWORK_ERROR)
                                        return
                                    }
                                }

                                // refresh the object in memory to check for externally requested cancel
                                outboxAttachment = OutboxAttachment.get(
                                    sendManagerSession,
                                    ownedIdentity,
                                    messageUid,
                                    attachmentNumber
                                )
                                if (outboxAttachment != null) {
                                    this.priority = outboxAttachment!!.priority
                                }
                            }
                            finished = true
                        }
                    } catch (_: FileNotFoundException) {
                        Logger.w("Attachment not found")
                        cancel(UploadAttachmentCompositeOperation.RFC_ATTACHMENT_FILE_NOT_READABLE)
                        return
                    }
                } catch (e: Exception) {
                    Logger.x(e)
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

    override fun getPriority(): Long {
        return priority
    }
}

internal class UploadAttachmentServerMethodForS3(
    private val url: String?,
    private val encryptedAttachmentChunk: EncryptedBytes
) : ServerMethodForS3() {
    override fun getUrl(): String? {
        return url
    }

    override fun getDataToSend(): ByteArray {
        return encryptedAttachmentChunk.getBytes()
    }

    override fun handleReceivedData(receivedData: ByteArray?) {
        // nothing to do;
    }

    override fun getMethod(): String {
        return METHOD_PUT
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }
}