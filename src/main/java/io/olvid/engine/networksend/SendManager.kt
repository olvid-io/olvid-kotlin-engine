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
package io.olvid.engine.networksend

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.MessageToSend
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NetworkSendDelegate
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import io.olvid.engine.networksend.coordinators.CancelAttachmentUploadCoordinator
import io.olvid.engine.networksend.coordinators.RefreshOutboxAttachmentSignedUrlCoordinator
import io.olvid.engine.networksend.coordinators.SendAttachmentCoordinator
import io.olvid.engine.networksend.coordinators.SendMessageCoordinator
import io.olvid.engine.networksend.coordinators.SendReturnReceiptCoordinator
import io.olvid.engine.networksend.databases.MessageHeader
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.databases.ReturnReceipt
import io.olvid.engine.networksend.datatypes.SendManagerSession
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import io.olvid.engine.storage.EngineFileIo
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory


class SendManager(
    metaManager: MetaManager,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    engineBaseDirectory: String?,
    fileIo: EngineFileIo,
    prng: PRNGService?,
    sendMessageThreadCount: Int,
    sendReturnReceiptThreadCount: Int
) : NetworkSendDelegate, SendManagerSessionFactory, ObvManager {
    private val engineBaseDirectory: String?
    private val fileIo: EngineFileIo
    private val sendMessageCoordinator: SendMessageCoordinator
    private val sendAttachmentCoordinator: SendAttachmentCoordinator
    private val cancelAttachmentUploadCoordinator: CancelAttachmentUploadCoordinator
    private val refreshOutboxAttachmentSignedUrlCoordinator: RefreshOutboxAttachmentSignedUrlCoordinator
    private val sendReturnReceiptCoordinator: SendReturnReceiptCoordinator

    private var createSessionDelegate: CreateSessionDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null
    private var identityDelegate: IdentityDelegate? = null

    init {
        this.engineBaseDirectory = engineBaseDirectory
        this.fileIo = fileIo
        this.sendMessageCoordinator =
            SendMessageCoordinator(this, sslSocketFactory, userAgentOverride, sendMessageThreadCount)
        this.refreshOutboxAttachmentSignedUrlCoordinator =
            RefreshOutboxAttachmentSignedUrlCoordinator(this, sslSocketFactory, userAgentOverride)
        this.sendAttachmentCoordinator = SendAttachmentCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            this.refreshOutboxAttachmentSignedUrlCoordinator
        )
        this.cancelAttachmentUploadCoordinator =
            CancelAttachmentUploadCoordinator(this, sslSocketFactory, userAgentOverride)
        this.sendReturnReceiptCoordinator =
            SendReturnReceiptCoordinator(this, sslSocketFactory, userAgentOverride, prng, sendReturnReceiptThreadCount)

        metaManager.requestDelegate(this, CreateSessionDelegate::class.java)
        metaManager.requestDelegate(this, NotificationPostingDelegate::class.java)
        metaManager.requestDelegate(this, NotificationListeningDelegate::class.java)
        metaManager.requestDelegate(this, IdentityDelegate::class.java)
        metaManager.registerImplementedDelegates(this)
    }

    override fun initialQueueingPriority(): Int {
        return 10
    }

    override fun initialisationComplete() {
        sendMessageCoordinator.initialQueueing()
        sendAttachmentCoordinator.initialQueueing()
        cancelAttachmentUploadCoordinator.initialQueueing()
        sendReturnReceiptCoordinator.initialQueueing()
    }

    fun startProcessing() {
        cancelAttachmentUploadCoordinator.startProcessing()
        refreshOutboxAttachmentSignedUrlCoordinator.startProcessing()
        sendAttachmentCoordinator.startProcessing()
        sendMessageCoordinator.startProcessing()
        sendReturnReceiptCoordinator.startProcessing()
    }

    fun setDelegate(createSessionDelegate: CreateSessionDelegate) {
        this.createSessionDelegate = createSessionDelegate

        try {
            session.use { sendManagerSession ->
                OutboxMessage.createTable(sendManagerSession.session)
                OutboxAttachment.createTable(sendManagerSession.session)
                MessageHeader.createTable(sendManagerSession.session)
                ReturnReceipt.createTable(sendManagerSession.session)
                sendManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to create network fetch databases")
        }
    }

    fun setDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
        if (notificationPostingDelegate != null) {
            this.refreshOutboxAttachmentSignedUrlCoordinator.setNotificationPostingDelegate(
                notificationPostingDelegate
            )
        }
    }

    fun setDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.sendAttachmentCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.cancelAttachmentUploadCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.sendMessageCoordinator.setNotificationListeningDelegate(notificationListeningDelegate)
        this.refreshOutboxAttachmentSignedUrlCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.sendReturnReceiptCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
    }

    fun setDelegate(identityDelegate: IdentityDelegate?) {
        this.identityDelegate = identityDelegate
    }


    @Throws(SQLException::class)
    fun deleteOwnedIdentity(session: Session, ownedIdentity: Identity) {
        // Delete all OutboxMessage (this deletes MessageHeader and OutboxAttachment)
        val outboxMessages: Array<OutboxMessage?> =
            OutboxMessage.getAllForOwnedIdentity(wrapSession(session), ownedIdentity)
        for (outboxMessage in outboxMessages) {
            outboxMessage?.delete()
        }
        // delete all ReturnReceipt
        ReturnReceipt.deleteAllForOwnedIdentity(wrapSession(session), ownedIdentity)
    }

    // region implement NetworkSendDelegate
    override fun post(session: Session, messageToSend: MessageToSend?) {
        if (messageToSend == null) return
        val sendManagerSession = wrapSession(session)

        OutboxMessage.create(
            sendManagerSession,
            messageToSend.getOwnedIdentity(),
            messageToSend.getUid(),
            messageToSend.getServer(),
            messageToSend.getEncryptedContent(),
            messageToSend.getEncryptedExtendedContent(),
            messageToSend.isApplicationMessage(),
            messageToSend.isVoipMessage(),
            messageToSend.getAttachments() != null && messageToSend.getAttachments()!!.size != 0
        )

        if (messageToSend.getHeaders() != null) {
            for (header in messageToSend.getHeaders()!!) {
                MessageHeader.create(
                    sendManagerSession,
                    messageToSend.getOwnedIdentity(),
                    messageToSend.getUid(),
                    header!!.getDeviceUid(),
                    header.getToIdentity(),
                    header.wrappedMessageKey
                )
            }
        }

        if (messageToSend.getAttachments() != null) {
            var attachmentNumber = 0
            for (attachment in messageToSend.getAttachments()!!) {
                OutboxAttachment.create(
                    sendManagerSession,
                    messageToSend.getOwnedIdentity(),
                    messageToSend.getUid(),
                    attachmentNumber,
                    attachment!!.getUrl(),
                    attachment.isDeleteAfterSend(),
                    attachment.getAttachmentLength(),
                    attachment.key
                )
                attachmentNumber++
            }
        }
    }

    @Throws(SQLException::class)
    override fun cancelAttachmentUpload(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        val outboxAttachment: OutboxAttachment? = OutboxAttachment.get(
            wrapSession(session),
            ownedIdentity,
            messageUid,
            attachmentNumber
        )
        outboxAttachment?.setCancelExternallyRequested()
    }

    @Throws(SQLException::class)
    override fun isOutboxAttachmentSent(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ): Boolean {
        val outboxAttachment: OutboxAttachment? = OutboxAttachment.get(
            wrapSession(session),
            ownedIdentity,
            messageUid,
            attachmentNumber
        )
        return (outboxAttachment == null) || outboxAttachment.isAcknowledged
    }

    @Throws(SQLException::class)
    override fun isOutboxMessageSent(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?
    ): Boolean {
        val outboxMessage: OutboxMessage? =
            OutboxMessage.get(wrapSession(session), ownedIdentity, messageUid)
        return (outboxMessage == null) || outboxMessage.isAcknowledged
    }

    @Throws(SQLException::class)
    override fun cancelMessageSending(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?
    ) {
        val outboxMessage: OutboxMessage? =
            OutboxMessage.get(wrapSession(session), ownedIdentity, messageUid)
        if (outboxMessage != null) {
            if (outboxMessage.isAcknowledged) {
                // if message is already sent, cancel all attachments (if any)
                for (outboxAttachment in outboxMessage.attachments ?: emptyArray()) {
                    outboxAttachment?.setCancelExternallyRequested()
                }
            } else {
                // simply simulate a messageUidFromServer so the operation finishes
                outboxMessage.setUidFromServer(UID(ByteArray(UID.UID_LENGTH)), ByteArray(0), 0)
                for (outboxAttachment in outboxMessage.attachments ?: emptyArray()) {
                    outboxAttachment?.setCancelExternallyRequested()
                    outboxAttachment?.setCancelProcessed()
                }
            }
        }
    }

    fun sendReturnReceipt(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUids: Array<UID?>?,
        status: Int,
        returnReceiptNonce: ByteArray?,
        returnReceiptKey: AuthEncKey?,
        attachmentNumber: Int?
    ) {
        // send is auto triggered on insertion commit
        ReturnReceipt.create(
            wrapSession(session),
            ownedIdentity,
            contactIdentity,
            contactDeviceUids ?: emptyArray(),
            status,
            returnReceiptNonce,
            returnReceiptKey,
            attachmentNumber
        )
    }

    override fun retryScheduledNetworkTasks() {
        cancelAttachmentUploadCoordinator.retryScheduledNetworkTasks()
        refreshOutboxAttachmentSignedUrlCoordinator.retryScheduledNetworkTasks()
        sendAttachmentCoordinator.retryScheduledNetworkTasks()
        sendMessageCoordinator.retryScheduledNetworkTasks()
        sendReturnReceiptCoordinator.retryScheduledNetworkTasks()
    }

    // endregion
    @get:Throws(SQLException::class)
    override val session: SendManagerSession
        get() {
            if (createSessionDelegate == null) {
                throw SQLException("No CreateSessionDelegate was set in SendManager.")
            }
            return SendManagerSession(
                createSessionDelegate!!.session,
                sendMessageCoordinator,
                sendAttachmentCoordinator,
                cancelAttachmentUploadCoordinator,
                notificationPostingDelegate,
                sendReturnReceiptCoordinator,
                identityDelegate,
                engineBaseDirectory,
                fileIo
            )
        }

    private fun wrapSession(session: Session): SendManagerSession {
        return SendManagerSession(
            session,
            sendMessageCoordinator,
            sendAttachmentCoordinator,
            cancelAttachmentUploadCoordinator,
            notificationPostingDelegate,
            sendReturnReceiptCoordinator,
            identityDelegate,
            engineBaseDirectory,
            fileIo
        )
    }

    companion object {
        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            OutboxMessage.upgradeTable(session, oldVersion, newVersion)
            OutboxAttachment.upgradeTable(session, oldVersion, newVersion)
            MessageHeader.upgradeTable(session, oldVersion, newVersion)
            ReturnReceipt.upgradeTable(session, oldVersion, newVersion)
        }
    }
}
