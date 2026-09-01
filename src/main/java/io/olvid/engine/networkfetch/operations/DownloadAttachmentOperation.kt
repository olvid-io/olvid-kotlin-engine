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
import io.olvid.engine.datatypes.Chunk
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.EtaEstimator
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PriorityOperation
import io.olvid.engine.datatypes.ServerMethodForS3
import io.olvid.engine.datatypes.ServerMethodForS3.ServerMethodForS3ProgressListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.coordinators.DownloadAttachmentCoordinator
import io.olvid.engine.networkfetch.databases.InboxAttachment
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.lang.ref.WeakReference
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class DownloadAttachmentOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val messageUid: UID,
    @JvmField val attachmentNumber: Int,
    @JvmField val priorityCategory: Int, // will be updated as the attachment is downloaded, so cannot be final
    private var priority: Long,
    coordinator: DownloadAttachmentCoordinator?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : PriorityOperation(
    InboxAttachment.computeUniqueUid(
        ownedIdentity,
        messageUid,
        attachmentNumber
    ), onFinishCallback, onCancelCallback
) {
    private val coordinatorWeakReference: WeakReference<DownloadAttachmentCoordinator?>

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    @JvmField var attachment: InboxAttachment? = null

    init {
        coordinatorWeakReference = WeakReference<DownloadAttachmentCoordinator?>(coordinator)
    }


    override fun doExecute() {
        var finished = false
        attachment = null
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    attachment = InboxAttachment.get(
                        fetchManagerSession,
                        ownedIdentity,
                        messageUid,
                        attachmentNumber
                    )
                    if (attachment == null) {
                        cancel(RFC_ATTACHMENT_CANNOT_BE_FOUND)
                        return
                    }
                    if (attachment!!.isMarkedForDeletion) {
                        cancel(RFC_MARKED_FOR_DELETION)
                        return
                    }
                    if (attachment!!.cannotBeFetched()) {
                        cancel(RFC_ATTACHMENT_CANNOT_BE_FETCHED)
                        return
                    }

                    if (!attachment!!.isDownloadRequested) {
                        cancel(RFC_FETCH_NOT_REQUESTED)
                        return
                    }

                    val etaEstimator = EtaEstimator(
                        attachment!!.receivedLength,
                        attachment!!.expectedLength
                    )

                    while (attachment!!.receivedLength != attachment!!.expectedLength) {
                        if (cancelWasRequested()) {
                            return
                        }
                        if (attachment!!.isMarkedForDeletion) {
                            cancel(RFC_MARKED_FOR_DELETION)
                            return
                        }
                        if (!attachment!!.isDownloadRequested) {
                            cancel(RFC_DOWNLOAD_PAUSED)
                            return
                        }
                        if (attachment!!.isUploadCancelledBySender) {
                            cancel(RFC_UPLOAD_CANCELLED_BY_SENDER)
                            return
                        }
                        val downloadUrls = attachment!!.getChunkDownloadPrivateUrls()
                        if (downloadUrls.size == 0) {
                            cancel(RFC_INVALID_SIGNED_URL)
                            return
                        }
                        // TODO 2026-06-06
                        //   ==> this can be removed once all inbox attachments have been created using server-API-21-compatible code
                        if (downloadUrls[attachment!!.receivedChunkCount].isNullOrEmpty()) {
                            cancel(RFC_UPLOAD_CANCELLED_BY_SENDER)
                            return
                        }

                        val serverMethod = DownloadAttachmentServerMethodForS3(
                            downloadUrls[attachment!!.receivedChunkCount]
                        )
                        serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)
                        serverMethod.setProgressListener(
                            150,
                            object : ServerMethodForS3ProgressListener {
                                val userInfo: HashMap<String, Any> = HashMap<String, Any>().also { map ->
                                    map[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_OWNED_IDENTITY_KEY] = ownedIdentity
                                    map[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_UID_KEY] = messageUid
                                    map[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY] = attachmentNumber
                                }

                                override fun onProgress(byteCount: Long) {
                                    val progress =
                                        (attachment!!.receivedLength + byteCount).toFloat() / attachment!!.expectedLength
                                    userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY] = progress
                                    etaEstimator.update(attachment!!.receivedLength + byteCount)
                                    val speedAndEta = etaEstimator.speedAndEta
                                    userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_SPEED_BPS_KEY] = speedAndEta.speedBps
                                    userInfo[DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ETA_SECONDS_KEY] = speedAndEta.etaSeconds
                                    fetchManagerSession.notificationPostingDelegate?.postNotification(
                                        DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS,
                                        userInfo
                                    )
                                }
                            })

                        val returnStatus = serverMethod.execute(
                            fetchManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                                fetchManagerSession.session,
                                ownedIdentity
                            )
                        )

                        fetchManagerSession.session.startTransaction()
                        when (returnStatus) {
                            ServerMethodForS3.OK -> {
                                val encryptedChunk = serverMethod.getEncryptedChunk()
                                val attachmentChunk: Chunk?
                                if (encryptedChunk.length != attachment!!.chunkLength &&
                                    attachment!!.receivedLength + encryptedChunk.length != attachment!!.expectedLength
                                ) {
                                    cancel(RFC_INVALID_CHUNK)
                                    return
                                }
                                try {
                                    val key = attachment!!.key
                                    val authEnc = Suite.getAuthEnc(key)!!
                                    val encodedChunk = Encoded(authEnc.decrypt(key, encryptedChunk)!!)
                                    attachmentChunk = Chunk.of(encodedChunk)
                                } catch (_: Exception) {
                                    cancel(RFC_DECRYPTION_ERROR)
                                    return
                                }
                                if (attachmentChunk.chunkNumber != attachment!!.receivedChunkCount) {
                                    cancel(RFC_INVALID_CHUNK)
                                    return
                                }
                                val success = attachment!!.writeToAttachmentFile(
                                    attachmentChunk.data,
                                    encryptedChunk.length
                                )
                                if (!success) {
                                    cancel(RFC_UNABLE_TO_WRITE_CHUNK_TO_FILE)
                                    return
                                }
                                fetchManagerSession.session.commit()
                                val coordinator = coordinatorWeakReference.get()
                                if (coordinator != null) {
                                    coordinator.resetFailedAttemptCount(
                                        ownedIdentity,
                                        messageUid,
                                        attachmentNumber
                                    )
                                }
                            }

                            ServerMethodForS3.INVALID_SIGNED_URL -> {
                                cancel(RFC_INVALID_SIGNED_URL)
                                return
                            }

                            ServerMethodForS3.NOT_FOUND -> {
                                cancel(RFC_NOT_FOUND_ON_SERVER)
                                return
                            }

                            ServerMethodForS3.IDENTITY_IS_NOT_ACTIVE -> {
                                cancel(RFC_IDENTITY_IS_INACTIVE)
                                return
                            }

                            else -> {
                                cancel(RFC_NETWORK_ERROR)
                                return
                            }
                        }

                        // refresh the object in memory to check for externally requested cancel
                        attachment = InboxAttachment.get(
                            fetchManagerSession,
                            ownedIdentity,
                            messageUid,
                            attachmentNumber
                        )
                        this.priority = attachment!!.priority
                    }
                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                    fetchManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        fetchManagerSession.session.commit()
                        setFinished()
                    } else {
                        fetchManagerSession.session.rollback()
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

    companion object {
        // possible reasons for cancel
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_INVALID_SIGNED_URL: Int = 2
        const val RFC_ATTACHMENT_CANNOT_BE_FOUND: Int = 3
        const val RFC_DECRYPTION_ERROR: Int = 5
        const val RFC_ATTACHMENT_CANNOT_BE_FETCHED: Int = 6
        const val RFC_NOT_FOUND_ON_SERVER: Int = 7
        const val RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY: Int = 8
        const val RFC_MARKED_FOR_DELETION: Int = 9
        const val RFC_FETCH_NOT_REQUESTED: Int = 10
        const val RFC_INVALID_CHUNK: Int = 11
        const val RFC_UNABLE_TO_WRITE_CHUNK_TO_FILE: Int = 12
        const val RFC_DOWNLOAD_PAUSED: Int = 13
        const val RFC_UPLOAD_CANCELLED_BY_SENDER: Int = 14
        const val RFC_IDENTITY_IS_INACTIVE: Int = 15
    }
}

internal class DownloadAttachmentServerMethodForS3(private val url: String?) : ServerMethodForS3() {
    private var encryptedChunk: EncryptedBytes? = null

    fun getEncryptedChunk(): EncryptedBytes {
        return encryptedChunk!!
    }

    override fun getUrl(): String? {
        return url
    }

    override fun getDataToSend(): ByteArray {
        return ByteArray(0)
    }

    override fun handleReceivedData(receivedData: ByteArray?) {
        encryptedChunk = EncryptedBytes(receivedData!!)
    }

    override fun getMethod(): String {
        return METHOD_GET
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }
}
