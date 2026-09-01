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
package io.olvid.engine.networkfetch

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AttachmentKeyAndMetadata
import io.olvid.engine.datatypes.containers.DecryptedApplicationMessage
import io.olvid.engine.datatypes.containers.OwnedIdentitySynchronizationStatus
import io.olvid.engine.datatypes.containers.ReceivedAttachment
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.engine.types.JsonOsmStyle
import io.olvid.engine.engine.types.ObvMessage
import io.olvid.engine.metamanager.ChannelDelegate
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NetworkFetchDelegate
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import io.olvid.engine.metamanager.ProcessDownloadedMessageDelegate
import io.olvid.engine.metamanager.PushNotificationDelegate
import io.olvid.engine.metamanager.SolveChallengeDelegate
import io.olvid.engine.networkfetch.coordinators.CreateServerSessionCoordinator
import io.olvid.engine.networkfetch.coordinators.DeleteMessageAndAttachmentsCoordinator
import io.olvid.engine.networkfetch.coordinators.DownloadAttachmentCoordinator
import io.olvid.engine.networkfetch.coordinators.DownloadMessageExtendedPayloadCoordinator
import io.olvid.engine.networkfetch.coordinators.DownloadMessagesAndListAttachmentsCoordinator
import io.olvid.engine.networkfetch.coordinators.FreeTrialCoordinator
import io.olvid.engine.networkfetch.coordinators.GetTurnCredentialsCoordinator
import io.olvid.engine.networkfetch.coordinators.RefreshInboxAttachmentSignedUrlCoordinator
import io.olvid.engine.networkfetch.coordinators.RegisterServerPushNotificationsCoordinator
import io.olvid.engine.networkfetch.coordinators.ServerQueryCoordinator
import io.olvid.engine.networkfetch.coordinators.ServerUserDataCoordinator
import io.olvid.engine.networkfetch.coordinators.VerifyReceiptCoordinator
import io.olvid.engine.networkfetch.coordinators.WebsocketCoordinator
import io.olvid.engine.networkfetch.coordinators.WellKnownCoordinator
import io.olvid.engine.networkfetch.coordinators.WellKnownCoordinator.NotCachedException
import io.olvid.engine.networkfetch.databases.CachedWellKnown
import io.olvid.engine.networkfetch.databases.InboxAttachment
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.databases.PendingServerQuery
import io.olvid.engine.networkfetch.databases.PushNotificationConfiguration
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import io.olvid.engine.storage.EngineFileIo
import java.sql.SQLException
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory


class FetchManager(
    metaManager: MetaManager,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    engineBaseDirectory: String?,
    fileIo: EngineFileIo,
    prng: PRNGService,
    jsonObjectMapper: ObjectMapper?
) : FetchManagerSessionFactory, NetworkFetchDelegate, PushNotificationDelegate, ObvManager {
    private val engineBaseDirectory: String?
    private val fileIo: EngineFileIo
    private val prng: PRNGService
    private val createServerSessionCoordinator: CreateServerSessionCoordinator
    private val refreshInboxAttachmentSignedUrlCoordinator: RefreshInboxAttachmentSignedUrlCoordinator
    private val downloadAttachmentCoordinator: DownloadAttachmentCoordinator
    private val downloadMessagesAndListAttachmentsCoordinator: DownloadMessagesAndListAttachmentsCoordinator
    private val downloadMessageExtendedPayloadCoordinator: DownloadMessageExtendedPayloadCoordinator
    private val deleteMessageAndAttachmentsCoordinator: DeleteMessageAndAttachmentsCoordinator
    private val registerServerPushNotificationsCoordinator: RegisterServerPushNotificationsCoordinator
    private val websocketCoordinator: WebsocketCoordinator
    private val serverQueryCoordinator: ServerQueryCoordinator
    private val serverUserDataCoordinator: ServerUserDataCoordinator
    private val getTurnCredentialsCoordinator: GetTurnCredentialsCoordinator
    private val freeTrialCoordinator: FreeTrialCoordinator
    private val verifyReceiptCoordinator: VerifyReceiptCoordinator
    private val wellKnownCoordinator: WellKnownCoordinator
    private var notificationPostingDelegate: NotificationPostingDelegate? = null
    private var identityDelegate: IdentityDelegate? = null
    private var processDownloadedMessageDelegate: ProcessDownloadedMessageDelegate? = null
    private var createSessionDelegate: CreateSessionDelegate? = null

    private val ownedIdentitiesUpToDateRegardingServerListing: HashSet<Identity?>

    init {
        this.engineBaseDirectory = engineBaseDirectory
        this.fileIo = fileIo
        this.prng = prng
        this.createServerSessionCoordinator =
            CreateServerSessionCoordinator(this, sslSocketFactory, userAgentOverride)
        this.refreshInboxAttachmentSignedUrlCoordinator =
            RefreshInboxAttachmentSignedUrlCoordinator(this, sslSocketFactory, userAgentOverride)
        this.downloadAttachmentCoordinator = DownloadAttachmentCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            this.refreshInboxAttachmentSignedUrlCoordinator
        )
        this.downloadMessagesAndListAttachmentsCoordinator =
            DownloadMessagesAndListAttachmentsCoordinator(
                this,
                sslSocketFactory,
                userAgentOverride,
                createServerSessionCoordinator
            )
        this.downloadMessageExtendedPayloadCoordinator = DownloadMessageExtendedPayloadCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            createServerSessionCoordinator
        )
        this.deleteMessageAndAttachmentsCoordinator = DeleteMessageAndAttachmentsCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            createServerSessionCoordinator
        )
        this.registerServerPushNotificationsCoordinator =
            RegisterServerPushNotificationsCoordinator(
                this,
                sslSocketFactory,
                userAgentOverride,
                createServerSessionCoordinator,
                downloadMessagesAndListAttachmentsCoordinator
            )
        this.downloadMessagesAndListAttachmentsCoordinator.setRegisterServerPushNotificationDelegate(
            this.registerServerPushNotificationsCoordinator
        )
        this.serverUserDataCoordinator = ServerUserDataCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            createServerSessionCoordinator,
            jsonObjectMapper!!,
            prng
        )
        this.serverQueryCoordinator = ServerQueryCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            prng,
            createServerSessionCoordinator,
            serverUserDataCoordinator,
            jsonObjectMapper
        )
        this.freeTrialCoordinator = FreeTrialCoordinator(this, sslSocketFactory, userAgentOverride)
        this.verifyReceiptCoordinator = VerifyReceiptCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            createServerSessionCoordinator
        )
        this.wellKnownCoordinator =
            WellKnownCoordinator(this, sslSocketFactory, userAgentOverride, jsonObjectMapper)
        this.websocketCoordinator = WebsocketCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            createServerSessionCoordinator,
            downloadMessagesAndListAttachmentsCoordinator,
            wellKnownCoordinator,
            jsonObjectMapper
        )
        this.getTurnCredentialsCoordinator = GetTurnCredentialsCoordinator(
            this,
            sslSocketFactory,
            userAgentOverride,
            createServerSessionCoordinator,
            wellKnownCoordinator
        )

        ownedIdentitiesUpToDateRegardingServerListing = HashSet<Identity?>()

        metaManager.requestDelegate(this, CreateSessionDelegate::class.java)
        metaManager.requestDelegate(this, SolveChallengeDelegate::class.java)
        metaManager.requestDelegate(this, ProcessDownloadedMessageDelegate::class.java)
        metaManager.requestDelegate(this, NotificationListeningDelegate::class.java)
        metaManager.requestDelegate(this, NotificationPostingDelegate::class.java)
        metaManager.requestDelegate(this, ChannelDelegate::class.java)
        metaManager.requestDelegate(this, IdentityDelegate::class.java)
        metaManager.requestDelegate(this, ProtocolStarterDelegate::class.java)
        metaManager.registerImplementedDelegates(this)
    }

    // region setDelegates
    override fun initialQueueingPriority(): Int {
        return 0
    }

    override fun initialisationComplete() {
        // we optimize the initial queueing order so web sockets connect as soon as possible and messages are listed soon too.
        wellKnownCoordinator.initialQueueing()
        websocketCoordinator.initialQueueing()
        downloadMessagesAndListAttachmentsCoordinator.initialQueueing()
        registerServerPushNotificationsCoordinator.initialQueueing()
        downloadAttachmentCoordinator.initialQueueing()
        serverQueryCoordinator.initialQueueing()
        downloadMessageExtendedPayloadCoordinator.initialQueueing()
        serverUserDataCoordinator.initialQueueing()
        createServerSessionCoordinator.initialQueueing()
    }

    fun startProcessing() {
        createServerSessionCoordinator.startProcessing()
        deleteMessageAndAttachmentsCoordinator.startProcessing()
        downloadAttachmentCoordinator.startProcessing()
        downloadMessageExtendedPayloadCoordinator.startProcessing()
        downloadMessagesAndListAttachmentsCoordinator.startProcessing()
        freeTrialCoordinator.startProcessing()
        getTurnCredentialsCoordinator.startProcessing()
        refreshInboxAttachmentSignedUrlCoordinator.startProcessing()
        registerServerPushNotificationsCoordinator.startProcessing()
        serverQueryCoordinator.startProcessing()
        serverUserDataCoordinator.startProcessing()
        verifyReceiptCoordinator.startProcessing()
        websocketCoordinator.startProcessing()
        wellKnownCoordinator.startProcessing()
    }

    @Suppress("unused")
    fun setDelegate(createSessionDelegate: CreateSessionDelegate) {
        this.createSessionDelegate = createSessionDelegate

        try {
            newFetchManagerSession().use { fetchManagerSession ->
                CachedWellKnown.createTable(fetchManagerSession.session)
                ServerSession.createTable(fetchManagerSession.session)
                PushNotificationConfiguration.createTable(fetchManagerSession.session)
                InboxMessage.createTable(fetchManagerSession.session)
                InboxAttachment.createTable(fetchManagerSession.session)
                PendingServerQuery.createTable(fetchManagerSession.session)
                fetchManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to createCurrentDevice network fetch databases")
        }
    }

    @Suppress("unused")
    fun setDelegate(solveChallengeDelegate: SolveChallengeDelegate?) {
        this.createServerSessionCoordinator.setSolveChallengeDelegate(solveChallengeDelegate)
    }

    @Suppress("unused")
    fun setDelegate(processDownloadedMessageDelegate: ProcessDownloadedMessageDelegate) {
        this.processDownloadedMessageDelegate = processDownloadedMessageDelegate
        this.downloadMessagesAndListAttachmentsCoordinator.setProcessDownloadedMessageDelegate(
            processDownloadedMessageDelegate
        )
    }

    @Suppress("unused")
    fun setDelegate(notificationListeningDelegate: NotificationListeningDelegate) {
        this.registerServerPushNotificationsCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.websocketCoordinator.setNotificationListeningDelegate(notificationListeningDelegate)
        this.downloadMessagesAndListAttachmentsCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.downloadMessageExtendedPayloadCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.downloadAttachmentCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.deleteMessageAndAttachmentsCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.serverQueryCoordinator.setNotificationListeningDelegate(notificationListeningDelegate)
        this.refreshInboxAttachmentSignedUrlCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.serverUserDataCoordinator.setNotificationListeningDelegate(
            notificationListeningDelegate
        )
        this.verifyReceiptCoordinator.setNotificationListeningDelegate(notificationListeningDelegate)
    }

    @Suppress("unused")
    fun setDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
        this.registerServerPushNotificationsCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
        this.downloadAttachmentCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
        this.createServerSessionCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
        this.refreshInboxAttachmentSignedUrlCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
        this.downloadMessagesAndListAttachmentsCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
        this.downloadMessageExtendedPayloadCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
        this.websocketCoordinator.setNotificationPostingDelegate(notificationPostingDelegate)
        this.wellKnownCoordinator.setNotificationPostingDelegate(notificationPostingDelegate)
        this.getTurnCredentialsCoordinator.setNotificationPostingDelegate(
            notificationPostingDelegate
        )
    }

    @Suppress("unused")
    fun setDelegate(channelDelegate: ChannelDelegate?) {
        this.serverQueryCoordinator.setChannelDelegate(channelDelegate)
    }

    @Suppress("unused")
    fun setDelegate(identityDelegate: IdentityDelegate) {
        this.identityDelegate = identityDelegate
    }

    @Suppress("unused")
    fun setDelegate(protocolStarterDelegate: ProtocolStarterDelegate?) {
        this.websocketCoordinator.setProtocolStarterDelegate(protocolStarterDelegate)
        this.registerServerPushNotificationsCoordinator.setProtocolStarterDelegate(
            protocolStarterDelegate
        )
    }

    // endregion
    @Throws(SQLException::class)
    fun deleteOwnedIdentity(
        session: Session,
        ownedIdentity: Identity,
        doNotDeleteServerSession: Boolean
    ) {
        // Delete all InboxMessage (this deletes InboxAttachment)
        val inboxMessages: Array<InboxMessage> =
            InboxMessage.getAllForOwnedIdentity(wrapSession(session), ownedIdentity)
        for (inboxMessage in inboxMessages) {
            inboxMessage.delete()
        }
        for (pendingServerQuery in PendingServerQuery.getAll(wrapSession(session))) {
            try {
                val serverQuery = ServerQuery.of(pendingServerQuery!!.encodedQuery)
                if (ownedIdentity == serverQuery.getOwnedIdentity()) {
                    pendingServerQuery.delete()
                }
            } catch (_: DecodingException) {
                // bad encoded query --> delete it
                pendingServerQuery!!.delete()
            }
        }
        PushNotificationConfiguration.deleteForOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        if (doNotDeleteServerSession) {
            ServerSession.deleteForIdentity(wrapSession(session), ownedIdentity)
        }
    }

    // region FetchManagerSessionFactory
    @get:Throws(SQLException::class)
    @get:JvmName("getSessionNullable")
    override val session: FetchManagerSession
        get() = newFetchManagerSession()

    @Throws(SQLException::class)
    fun newFetchManagerSession(): FetchManagerSession {
        if (createSessionDelegate == null) {
            throw SQLException("No CreateSessionDelegate was set in FetchManager.")
        }
        return FetchManagerSession(
            createSessionDelegate!!.session,
            downloadMessagesAndListAttachmentsCoordinator,
            downloadMessageExtendedPayloadCoordinator,
            deleteMessageAndAttachmentsCoordinator,
            downloadAttachmentCoordinator,  //                deleteMessageAndAttachmentsCoordinator,
            registerServerPushNotificationsCoordinator,
            serverQueryCoordinator,
            identityDelegate,
            engineBaseDirectory,
            fileIo,
            notificationPostingDelegate,
            createServerSessionCoordinator
        )
    }

    private fun wrapSession(session: Session): FetchManagerSession {
        return FetchManagerSession(
            session,
            downloadMessagesAndListAttachmentsCoordinator,
            downloadMessageExtendedPayloadCoordinator,
            deleteMessageAndAttachmentsCoordinator,
            downloadAttachmentCoordinator,  //                deleteMessageAndAttachmentsCoordinator,
            registerServerPushNotificationsCoordinator,
            serverQueryCoordinator,
            identityDelegate,
            engineBaseDirectory,
            fileIo,
            notificationPostingDelegate,
            createServerSessionCoordinator
        )
    }

    // endregion
    // region implement NetworkFetchDelegate
    override fun downloadMessages(ownedIdentity: Identity?, deviceUid: UID?) {
        markOwnedIdentityAsNotUpToDate(
            ownedIdentity,
            OwnedIdentitySynchronizationStatus.MANUAL_SYNC_IN_PROGRESS
        )
        downloadMessagesAndListAttachmentsCoordinator.downloadMessagesAndListAttachments(
            ownedIdentity,
            deviceUid
        )

        val userInfo = HashMap<String, Any>()
        ownedIdentity?.let { userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED_OWNED_IDENTITY_KEY] = it }
        userInfo[DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED_USER_INITIATED_KEY] = true
        notificationPostingDelegate?.postNotification(
            DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED,
            userInfo
        )
    }

    override fun getMessage(
        ownedIdentity: Identity?,
        messageUid: UID?
    ): DecryptedApplicationMessage? {
        try {
            newFetchManagerSession().use { fetchManagerSession ->
                val inboxMessage: InboxMessage =
                    InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid)
                        ?: return null
                return inboxMessage.decryptedApplicationMessage
            }
        } catch (_: SQLException) {
            return null
        }
    }

    @Throws(Exception::class)
    override fun setAttachmentKeyAndMetadataAndMessagePayload(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        remoteIdentity: Identity?,
        remoteDeviceUid: UID?,
        attachmentKeyAndMetadata: Array<AttachmentKeyAndMetadata?>?,
        messagePayload: ByteArray?,
        extendedPayloadKey: AuthEncKey?
    ) {
        if (attachmentKeyAndMetadata == null) {
            Logger.e("FetchManager is trying to setAttachmentKeyAndMetadataAndMessagePayload with a null attachmentKeyAndMetadata.")
            throw Exception()
        }
        val fetchManagerSession = wrapSession(session)
        val inboxMessage: InboxMessage? =
            InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid)
        if (inboxMessage == null) {
            Logger.e("FetchManager is trying to setAttachmentKeyAndMetadataAndMessagePayload for an non-existing messageUid.")
            throw Exception()
        }
        val attachments = inboxMessage.attachments
        if (attachments!!.size != attachmentKeyAndMetadata.size) {
            Logger.e("Attachment count mismatch between message and attachmentKeyAndMetadata in setAttachmentKeyAndMetadataAndMessagePayload.")
            throw Exception()
        }
        Logger.d("Setting attachmentKeyAndMetadata for " + attachments.size + " attachments.")
        for (i in attachments.indices) {
            attachments[i].setKeyAndMetadata(
                attachmentKeyAndMetadata[i]!!.getKey()!!,
                attachmentKeyAndMetadata[i]!!.getMetadata()!!
            )
        }
        inboxMessage.setPayloadAndFromIdentity(
            messagePayload,
            remoteIdentity!!,
            remoteDeviceUid,
            extendedPayloadKey,
            attachments as Array<InboxAttachment>?
        )
        // just in case, also mark recentlyOnline as true (otherwise, a contact could remain not recently online until a contact discovery)
        identityDelegate!!.setContactRecentlyOnline(session, ownedIdentity, remoteIdentity, true)
    }

    @Throws(Exception::class)
    override fun setInboxMessageFromIdentityForMissingPreKeyContact(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        contactIdentity: Identity?
    ) {
        val fetchManagerSession = wrapSession(session)
        val inboxMessage: InboxMessage? =
            InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid)
        if (inboxMessage == null) {
            Logger.e("FetchManager is trying to setInboxMessageFromIdentityForMissingPreKeyContact for an non-existing messageUid.")
            throw Exception()
        }
        inboxMessage.setFromIdentityForMissingPreKeyContact(contactIdentity!!)
    }

    override fun downloadAttachment(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        priorityCategory: Int
    ) {
        try {
            newFetchManagerSession().use { fetchManagerSession ->
                val inboxAttachment: InboxAttachment? = InboxAttachment.get(
                    fetchManagerSession,
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
                if (inboxAttachment == null) {
                    Logger.e("FetchManager received a downloadAttachment request for an unknown attachment " + messageUid + "-" + attachmentNumber)
                    return
                }
                if (inboxAttachment.cannotBeFetched()) {
                    Logger.e("FetchManager received a downloadAttachment request for an attachment that cannot be fetched " + messageUid + "-" + attachmentNumber)
                    return
                }
                inboxAttachment.requestDownload(priorityCategory)
                fetchManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.e("FetchManager was unable to downloadAttachment " + messageUid + "-" + attachmentNumber)
        }
    }

    override fun pauseDownloadAttachment(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        try {
            newFetchManagerSession().use { fetchManagerSession ->
                val inboxAttachment: InboxAttachment? = InboxAttachment.get(
                    fetchManagerSession,
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
                if (inboxAttachment == null) {
                    Logger.e("FetchManager received a pauseDownloadAttachment request for an unknown attachment " + messageUid + "-" + attachmentNumber)
                    return
                }
                inboxAttachment.pauseDownload()
                fetchManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.e("FetchManager was unable to pauseDownloadAttachment " + messageUid + "-" + attachmentNumber)
        }
    }

    override fun getAttachment(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ): ReceivedAttachment? {
        try {
            newFetchManagerSession().use { fetchManagerSession ->
                val inboxAttachment: InboxAttachment? = InboxAttachment.get(
                    fetchManagerSession,
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
                if (inboxAttachment == null) {
                    Logger.e("FetchManager received a getAttachment request for an unknown attachment " + messageUid + "-" + attachmentNumber)
                    return null
                }
                if (inboxAttachment.cannotBeFetched()) {
                    Logger.e("FetchManager received a getAttachment request for an attachment not yet ready " + messageUid + "-" + attachmentNumber)
                    return null
                }
                return ReceivedAttachment(
                    inboxAttachment.getOwnedIdentity(),
                    inboxAttachment.messageUid,
                    inboxAttachment.attachmentNumber,
                    inboxAttachment.metadata,
                    inboxAttachment.url,
                    inboxAttachment.plaintextExpectedLength,
                    inboxAttachment.plaintextReceivedLength,
                    inboxAttachment.isUploadCancelledBySender,
                    inboxAttachment.isDownloadRequested
                )
            }
        } catch (e: SQLException) {
            Logger.e("FetchManager was unable to getAttachment " + messageUid + "-" + attachmentNumber)
            return null
        }
    }

    @Throws(Exception::class)
    override fun isInboxAttachmentReceived(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ): Boolean {
        val inboxAttachment: InboxAttachment? = InboxAttachment.get(
            wrapSession(session),
            ownedIdentity,
            messageUid,
            attachmentNumber
        )
        return (inboxAttachment == null) || (inboxAttachment.expectedLength == inboxAttachment.receivedLength)
    }


    // this method is called when a received message cannot be decrypted.
    // If we are still listing messages on the server, we may be late on self-ratchet so we simply postpone the processing of this message by doing nothing :)
    override fun messageCannotBeDecrypted(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?
    ) {
        synchronized(ownedIdentitiesUpToDateRegardingServerListing) {
            if (ownedIdentitiesUpToDateRegardingServerListing.contains(ownedIdentity)) {
                deleteMessageAndAttachments(session, ownedIdentity, messageUid)
            }
        }
    }

    override fun markOwnedIdentityAsUpToDate(ownedIdentity: Identity?) {
        synchronized(ownedIdentitiesUpToDateRegardingServerListing) {
            // mark the identity as up to date
            ownedIdentitiesUpToDateRegardingServerListing.add(ownedIdentity)

            // notify app that syncing is finished
            if (notificationPostingDelegate != null) {
                val userInfo = HashMap<String, Any>()
                ownedIdentity?.let { userInfo[DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_OWNED_IDENTITY_KEY] = it }
                userInfo[DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY] = OwnedIdentitySynchronizationStatus.SYNCHRONIZED
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER,
                    userInfo
                )
            }

            // reprocess all unprocessed messages
            try {
                newFetchManagerSession().use { fetchManagerSession ->
                    // retry processing messages that were downloaded but never decrypted nor marked for deletion
                    val unprocessedMessages: Array<InboxMessage> =
                        InboxMessage.getUnprocessedMessagesForOwnedIdentity(
                            fetchManagerSession,
                            ownedIdentity!!
                        )
                    for (inboxMessage in unprocessedMessages) {
                        processDownloadedMessageDelegate!!.processDownloadedMessage(inboxMessage.networkReceivedMessage)
                    }
                }
            } catch (_: SQLException) {
            }
        }
    }

    override fun markOwnedIdentityAsNotUpToDate(
        ownedIdentity: Identity?,
        synchronizationStatus: OwnedIdentitySynchronizationStatus?
    ) {
        synchronized(ownedIdentitiesUpToDateRegardingServerListing) {
            // notify app that syncing is in progress, but only if it was in sync
            ownedIdentitiesUpToDateRegardingServerListing.remove(ownedIdentity)
            if (notificationPostingDelegate != null && synchronizationStatus != OwnedIdentitySynchronizationStatus.SYNCHRONIZED) {
                val userInfo = HashMap<String, Any>()
                ownedIdentity?.let { userInfo[DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_OWNED_IDENTITY_KEY] = it }
                synchronizationStatus?.let { userInfo[DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY] = it }
                notificationPostingDelegate?.postNotification(
                    DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER,
                    userInfo
                )
            }
        }
    }

    // This method marks a message and all its attachments for deletion
    override fun deleteMessageAndAttachments(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?
    ) {
        val fetchManagerSession = wrapSession(session)
        val inboxMessage: InboxMessage =
            InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid) ?: return
        inboxMessage.markForDeletion()
        for (inboxAttachment in inboxMessage.attachments!!) {
            inboxAttachment.markForDeletion()
        }
        session.addSessionCommitListener {
            fetchManagerSession.markAsListedAndDeleteOnServerListener?.messageCanBeDeletedFromServer(
                ownedIdentity,
                messageUid
            )
        }
    }

    // This method marks a message for deletion and queues the operation to delete it from server
    override fun deleteMessage(session: Session, ownedIdentity: Identity?, messageUid: UID?) {
        val fetchManagerSession = wrapSession(session)
        val inboxMessage: InboxMessage =
            InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid) ?: return
        inboxMessage.markForDeletion()
        if (inboxMessage.canBeDeleted()) {
            session.addSessionCommitListener {
                fetchManagerSession.markAsListedAndDeleteOnServerListener?.messageCanBeDeletedFromServer(
                    ownedIdentity,
                    messageUid
                )
            }
        }
    }

    // This method marks an attachment for deletion and queues the operation to delete it from server
    @Throws(SQLException::class)
    override fun deleteAttachment(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ) {
        val fetchManagerSession = wrapSession(session)
        val inboxAttachment: InboxAttachment? = InboxAttachment.get(
            fetchManagerSession,
            ownedIdentity,
            messageUid,
            attachmentNumber
        )
        if (inboxAttachment == null) {
            return
        }
        inboxAttachment.markForDeletion()
        if (inboxAttachment.message?.canBeDeleted() == true) {
            fetchManagerSession.markAsListedAndDeleteOnServerListener!!.messageCanBeDeletedFromServer(
                ownedIdentity,
                messageUid
            )
        }
    }

    @Throws(SQLException::class)
    override fun markMessageAsOnHold(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?
    ) {
        val fetchManagerSession = wrapSession(session)
        val inboxMessage: InboxMessage =
            InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid) ?: return
        inboxMessage.markAsOnHold()
    }

    @Throws(Exception::class)
    override fun resendAllDownloadedAttachmentNotifications() {
        newFetchManagerSession().use { fetchManagerSession ->
            val inboxAttachments: Array<InboxAttachment> =
                InboxAttachment.getAllDownloaded(fetchManagerSession)
            for (inboxAttachment in inboxAttachments) {
                downloadAttachmentCoordinator.attachmentDownloadFinished(
                    inboxAttachment.getOwnedIdentity(),
                    inboxAttachment.messageUid,
                    inboxAttachment.attachmentNumber
                )
            }
        }
    }

    @Throws(Exception::class)
    override fun getOnHoldMessage(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?
    ): ObvMessage? {
        val fetchManagerSession = wrapSession(session)
        val inboxMessage: InboxMessage =
            InboxMessage.get(fetchManagerSession, ownedIdentity!!, messageUid)
                ?: throw Exception("Message not found in Inbox")
        val attachments = inboxMessage.attachments!!
        val receivedAttachmentsList = ArrayList<ReceivedAttachment>(attachments.size)
        for (i in attachments.indices) {
            receivedAttachmentsList.add(ReceivedAttachment(
                attachments[i].getOwnedIdentity(),
                attachments[i].messageUid,
                attachments[i].attachmentNumber,
                attachments[i].metadata,
                attachments[i].url,
                attachments[i].plaintextExpectedLength,
                attachments[i].plaintextReceivedLength,
                attachments[i].isUploadCancelledBySender,
                attachments[i].isDownloadRequested
            ))
        }
        return ObvMessage(inboxMessage.decryptedApplicationMessage!!, receivedAttachmentsList.toTypedArray())
    }

    @Throws(Exception::class)
    override fun createPendingServerQuery(session: Session, serverQuery: ServerQuery?) {
        val pendingServerQuery: PendingServerQuery =
            PendingServerQuery.create(wrapSession(session), serverQuery, prng)
                ?: throw Exception()
    }


    override fun deleteExistingServerSession(
        session: Session,
        ownedIdentity: Identity?,
        createNewSession: Boolean
    ) {
        ServerSession.deleteForIdentity(wrapSession(session), ownedIdentity)
        if (createNewSession) {
            createServerSessionCoordinator.createServerSession(ownedIdentity)
        }
    }

    fun createServerSession(ownedIdentity: Identity?) {
        createServerSessionCoordinator.createServerSession(ownedIdentity)
    }

    override fun connectWebsockets(
        relyOnWebsocketForNetworkDetection: Boolean,
        os: String?,
        osVersion: String?,
        appBuild: Int,
        appVersion: String?
    ) {
        if ("javax.net.ssl.HttpsURLConnection.DefaultHostnameVerifier" == HttpsURLConnection.getDefaultHostnameVerifier().javaClass.getCanonicalName()) {
            Logger.w("WARNING: default HostnameVerifier not set. Websocket connection will most probably fail.\n\tYou may want to consider using OkHttp's HostnameVerifier as the default with:\n\t\tHttpsURLConnection.setDefaultHostnameVerifier(OkHostnameVerifier.INSTANCE);")
        }
        websocketCoordinator.connectWebsockets(
            relyOnWebsocketForNetworkDetection,
            os,
            osVersion,
            appBuild,
            appVersion
        )
    }

    override fun disconnectWebsockets() {
        websocketCoordinator.disconnectWebsockets()
    }

    override fun pingWebsocket(ownedIdentity: Identity?) {
        websocketCoordinator.pingWebsocket(ownedIdentity!!)
    }

    override fun getServerAuthenticationToken(ownedIdentity: Identity?): ByteArray? {
        try {
            newFetchManagerSession().use { fetchManagerSession ->
                return ServerSession.getToken(fetchManagerSession, ownedIdentity)
            }
        } catch (e: SQLException) {
            Logger.x(e)
            return null
        }
    }

    override fun retryScheduledNetworkTasks() {
        createServerSessionCoordinator.retryScheduledNetworkTasks()
        deleteMessageAndAttachmentsCoordinator.retryScheduledNetworkTasks()
        downloadAttachmentCoordinator.retryScheduledNetworkTasks()
        downloadMessagesAndListAttachmentsCoordinator.retryScheduledNetworkTasks()
        downloadMessageExtendedPayloadCoordinator.retryScheduledNetworkTasks()
        refreshInboxAttachmentSignedUrlCoordinator.retryScheduledNetworkTasks()
        registerServerPushNotificationsCoordinator.retryScheduledNetworkTasks()
        serverQueryCoordinator.retryScheduledNetworkTasks()
        websocketCoordinator.retryScheduledNetworkTasks()
    }

    override fun getTurnCredentials(
        ownedIdentity: Identity?,
        callUuid: UUID?,
        username1: String?,
        username2: String?
    ) {
        getTurnCredentialsCoordinator.getTurnCredentials(
            ownedIdentity!!,
            callUuid,
            username1,
            username2
        )
    }

    override fun getWellKnownTurnServers(ownedIdentity: Identity?): MutableList<String>? {
        try {
            return wellKnownCoordinator.getTurnUrls(ownedIdentity!!.server)
        } catch (_: NotCachedException) {
        }
        return null
    }

    override fun getWellKnownAltTurnServers(ownedIdentity: Identity?): MutableList<String>? {
        try {
            return wellKnownCoordinator.getAltTurnUrls(ownedIdentity!!.server)
        } catch (_: NotCachedException) {
        }
        return null
    }

    override fun queryApiKeyStatus(ownedIdentity: Identity?, apiKey: UUID?) {
        createServerSessionCoordinator.queueNewQueryApiKeyStatusOperation(ownedIdentity, apiKey)
    }

    override fun queryFreeTrial(ownedIdentity: Identity?) {
        freeTrialCoordinator.queryFreeTrial(ownedIdentity!!)
    }

    override fun startFreeTrial(ownedIdentity: Identity?) {
        freeTrialCoordinator.startFreeTrial(ownedIdentity!!)
    }

    override fun verifyReceipt(ownedIdentity: Identity?, storeToken: String?) {
        verifyReceiptCoordinator.verifyReceipt(ownedIdentity!!, storeToken)
    }

    override fun queryServerWellKnown(server: String?) {
        wellKnownCoordinator.queueNewWellKnownDownloadOperation(server)
    }

    override fun getOsmStyles(server: String?): MutableList<JsonOsmStyle>? {
        try {
            return wellKnownCoordinator.getOsmStyles(server)
        } catch (_: Exception) {
            return null
        }
    }

    override fun getAddressServerUrl(server: String?): String? {
        try {
            return wellKnownCoordinator.getAddressUrl(server)
        } catch (_: Exception) {
            return null
        }
    }

    // endregion
    // region implement PushNotificationDelegate
    @Throws(SQLException::class)
    override fun registerPushNotificationIfConfigurationChanged(
        session: Session,
        ownedIdentity: Identity?,
        currentDeviceUid: UID?,
        newPushParameters: PushNotificationTypeAndParameters?
    ) {
        val fetchManagerSession = wrapSession(session)
        val pushNotificationConfiguration: PushNotificationConfiguration? =
            PushNotificationConfiguration.get(fetchManagerSession, ownedIdentity)
        if (pushNotificationConfiguration != null) {
            if (pushNotificationConfiguration.deviceUid.equals(currentDeviceUid)) {
                val oldPushParameters =
                    pushNotificationConfiguration.pushNotificationTypeAndParameters
                if (oldPushParameters.sameTypeAndToken(newPushParameters!!)) {
                    // when parameters are equal, we only replace them in DB if it changed from a no-reactivate to a reactivate, or if the deviceUidToReplace has changed
                    if ((!oldPushParameters.reactivateCurrentDevice && newPushParameters.reactivateCurrentDevice) || (oldPushParameters.reactivateCurrentDevice && newPushParameters.reactivateCurrentDevice && (oldPushParameters.deviceUidToReplace != newPushParameters.deviceUidToReplace))) {
                        // tokens are the same, no need to change identityMaskingUid
                        newPushParameters.identityMaskingUid = oldPushParameters.identityMaskingUid
                    } else {
                        return
                    }
                } else {
                    // token has changed, or notification type has changed
                    // we still need to preserve the reactivateCurrentDevice and deviceUidToReplace parameters
                    if (oldPushParameters.reactivateCurrentDevice && !newPushParameters.reactivateCurrentDevice) {
                        newPushParameters.reactivateCurrentDevice = true
                        newPushParameters.deviceUidToReplace = oldPushParameters.deviceUidToReplace
                    }
                }
            }
            pushNotificationConfiguration.delete()
        }
        if (PushNotificationConfiguration.create(
                fetchManagerSession,
                ownedIdentity,
                currentDeviceUid,
                newPushParameters
            ) == null
        ) {
            throw SQLException()
        }
    }

    override fun processAndroidPushNotification(maskingUidString: String?) {
        registerServerPushNotificationsCoordinator.processAndroidPushNotification(maskingUidString)
    }

    override fun forceRegisterPushNotification(
        ownedIdentity: Identity?,
        triggerAnOwnedDeviceDiscoveryWhenFinished: Boolean
    ) {
        registerServerPushNotificationsCoordinator.registerServerPushNotification(
            ownedIdentity,
            triggerAnOwnedDeviceDiscoveryWhenFinished
        )
    }

    override fun getOwnedIdentityFromMaskingUid(maskingUidString: String?): Identity? {
        return registerServerPushNotificationsCoordinator.getOwnedIdentityFromMaskingUid(
            maskingUidString
        )
    }

    // endregion
    fun deleteReturnReceipt(ownedIdentity: Identity, serverUid: ByteArray?) {
        websocketCoordinator.deleteReturnReceipt(ownedIdentity, serverUid)
    }

    companion object {
        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            CachedWellKnown.upgradeTable(session, oldVersion, newVersion)
            ServerSession.upgradeTable(session, oldVersion, newVersion)
            PushNotificationConfiguration.upgradeTable(session, oldVersion, newVersion)
            InboxMessage.upgradeTable(session, oldVersion, newVersion)
            InboxAttachment.upgradeTable(session, oldVersion, newVersion)
            PendingServerQuery.upgradeTable(session, oldVersion, newVersion)
            if (oldVersion < 40 && newVersion >= 40) {
                Logger.d("DROPPING `pending_delete_from_server` DATABASE FOR VERSION 40")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE `pending_delete_from_server`")
                }
            }
        }
    }
}
