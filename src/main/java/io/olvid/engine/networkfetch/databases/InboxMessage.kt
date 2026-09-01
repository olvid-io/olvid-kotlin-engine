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
package io.olvid.engine.networkfetch.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.DecryptedApplicationMessage
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import java.io.IOException
import java.sql.ResultSet
import java.sql.SQLException
import kotlin.collections.toTypedArray

class InboxMessage : ObvDatabase {
    private val fetchManagerSession: FetchManagerSession

    private var ownedIdentity: Identity? = null
    @JvmField val uid: UID
    @JvmField val wrappedKey: EncryptedBytes?
    @JvmField val encryptedContent: EncryptedBytes?
    private var markedForDeletion: Boolean
    @JvmField val serverTimestamp: Long
    var payload: ByteArray?
        private set
    private var fromIdentity: Identity? = null
    private val downloadTimestamp: Long
    private val localDownloadTimestamp: Long
    private val hasExtendedPayload: Boolean
    var extendedPayloadKey: AuthEncKey? = null
        private set
    private var extendedPayload: ByteArray?
    private var fromDeviceUid: UID? = null
    private var onHold: Boolean
    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun getExtendedPayload(): ByteArray? {
        return extendedPayload
    }

    val attachments: Array<InboxAttachment>?
        get() = InboxAttachment.getAll(fetchManagerSession, ownedIdentity, uid)

    val networkReceivedMessage: NetworkReceivedMessage?
        get() {
            if ((encryptedContent == null) || (wrappedKey == null)) {
                return null
            }
            val header =
                NetworkReceivedMessage.Header(
                    ownedIdentity,
                    wrappedKey
                )
            return NetworkReceivedMessage(
                uid,
                serverTimestamp,
                encryptedContent,
                header,
                hasExtendedPayload
            )
        }

    val decryptedApplicationMessage: DecryptedApplicationMessage?
        get() {
            if ((payload == null) || (fromIdentity == null)) {
                return null
            }
            return DecryptedApplicationMessage(
                uid,
                payload,
                fromIdentity,
                fromDeviceUid,
                ownedIdentity,
                serverTimestamp,
                downloadTimestamp,
                localDownloadTimestamp
            )
        }

    fun canBeDeleted(): Boolean {
        if (!markedForDeletion) {
            return false
        }
        for (inboxAttachment in this.attachments ?: return true) {
            if (!inboxAttachment.isMarkedForDeletion) {
                return false
            }
        }
        return true
    }

    // region setters
    fun markForDeletion() {
        try {
            fetchManagerSession.session.prepareStatement(
                "InboxMessage.markForDeletion",
                "UPDATE " + TABLE_NAME +
                        " SET " + MARKED_FOR_DELETION + " = 1 " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + UID_ + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity!!.getBytes())
                statement.setBytes(2, uid.bytes)
                statement.executeUpdate()
                this.markedForDeletion = true
            }
        } catch (_: SQLException) {
        }
    }

    @Throws(SQLException::class)
    fun markAsOnHold() {
        fetchManagerSession.session.prepareStatement(
            "InboxMessage.markAsOnHold",
            "UPDATE " + TABLE_NAME +
                    " SET " + ON_HOLD + " = 1 " +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
            this.onHold = true
        }
    }

    fun setPayloadAndFromIdentity(
        payload: ByteArray?,
        fromIdentity: Identity,
        fromDeviceUid: UID?,
        extendedPayloadKey: AuthEncKey?,
        attachments: Array<InboxAttachment>?
    ) {
        try {
            fetchManagerSession.session.prepareStatement(
                "InboxMessage.setPayloadAndFromIdentity",
                "UPDATE " + TABLE_NAME +
                        " SET " + PAYLOAD + " = ?, " +
                        FROM_IDENTITY + " = ?, " +
                        FROM_DEVICE_UID + " = ?, " +
                        EXTENDED_PAYLOAD_KEY + " = ? " +
                        "WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + UID_ + " = ?;"
            ).use { statement ->
                statement.setBytes(1, payload)
                statement.setBytes(2, fromIdentity.getBytes())
                statement.setBytes(3, if (fromDeviceUid == null) null else fromDeviceUid.bytes)
                statement.setBytes(
                    4,
                    if (extendedPayloadKey == null) null else Encoded.of(extendedPayloadKey).bytes
                )
                statement.setBytes(5, ownedIdentity!!.getBytes())
                statement.setBytes(6, uid.bytes)
                statement.executeUpdate()
                this.payload = payload
                this.fromIdentity = fromIdentity
                this.fromDeviceUid = fromDeviceUid
                this.extendedPayloadKey = extendedPayloadKey
                attachmentsToNotify = attachments
                commitHookBits = commitHookBits or HOOK_BIT_PAYLOAD_AND_FROM_IDENTITY_SET
                fetchManagerSession.session.addSessionCommitListener(this)
            }
        } catch (_: SQLException) {
            // nothing
        }
    }

    fun setFromIdentityForMissingPreKeyContact(fromIdentity: Identity) {
        try {
            fetchManagerSession.session.prepareStatement(
                "InboxMessage.setFromIdentityForMissingPreKeyContact",
                "UPDATE " + TABLE_NAME +
                        " SET " + FROM_IDENTITY + " = ? " +
                        "WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + UID_ + " = ?;"
            ).use { statement ->
                statement.setBytes(1, fromIdentity.getBytes())
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setBytes(3, uid.bytes)
                statement.executeUpdate()
                this.fromIdentity = fromIdentity
            }
        } catch (_: SQLException) {
            // nothing
        }
    }

    @Throws(SQLException::class)
    fun setExtendedPayload(extendedPayload: ByteArray?) {
        fetchManagerSession.session.prepareStatement(
            "InboxMessage.setExtendedPayload",
            "UPDATE " + TABLE_NAME +
                    " SET " + EXTENDED_PAYLOAD + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, extendedPayload)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setBytes(3, uid.bytes)
            statement.executeUpdate()
            this.extendedPayload = extendedPayload
            commitHookBits = commitHookBits or HOOK_BIT_EXTENDED_PAYLOAD_SET
            fetchManagerSession.session.addSessionCommitListener(this)
        }
    }

    private constructor(
        fetchManagerSession: FetchManagerSession,
        ownedIdentity: Identity,
        messageUid: UID,
        encryptedContent: EncryptedBytes?,
        wrappedKey: EncryptedBytes?,
        serverTimestamp: Long,
        downloadTimestamp: Long,
        localDownloadTimestamp: Long,
        hasExtendedContent: Boolean
    ) {
        this.fetchManagerSession = fetchManagerSession
        this.uid = messageUid
        this.ownedIdentity = ownedIdentity
        this.encryptedContent = encryptedContent
        this.wrappedKey = wrappedKey
        this.markedForDeletion = false
        this.serverTimestamp = serverTimestamp
        this.payload = null
        this.fromIdentity = null
        this.fromDeviceUid = null
        this.downloadTimestamp = downloadTimestamp
        this.localDownloadTimestamp = localDownloadTimestamp
        this.hasExtendedPayload = hasExtendedContent
        this.extendedPayloadKey = null
        this.extendedPayload = null
        this.onHold = false
    }

    private constructor(fetchManagerSession: FetchManagerSession, res: ResultSet) {
        this.fetchManagerSession = fetchManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.uid = UID(res.getBytes(UID_))
        var bytes: ByteArray? = res.getBytes(WRAPPED_KEY)
        this.wrappedKey = if (bytes == null) null else EncryptedBytes(bytes)
        bytes = res.getBytes(ENCRYPTED_CONTENT)
        this.encryptedContent = if (bytes == null) null else EncryptedBytes(bytes)
        this.markedForDeletion = res.getBoolean(MARKED_FOR_DELETION)
        this.serverTimestamp = res.getLong(SERVER_TIMESTAMP)
        this.payload = res.getBytes(PAYLOAD)
        val fromIdentityBytes: ByteArray? = res.getBytes(FROM_IDENTITY)
        if (fromIdentityBytes == null) {
            this.fromIdentity = null
        } else {
            try {
                this.fromIdentity = Identity.of(fromIdentityBytes)
            } catch (e: DecodingException) {
                Logger.x(e)
            }
        }
        val fromDeviceUidBytes: ByteArray? = res.getBytes(FROM_DEVICE_UID)
        if (fromDeviceUidBytes == null || fromDeviceUidBytes.size != UID.UID_LENGTH) {
            this.fromDeviceUid = null
        } else {
            this.fromDeviceUid = UID(fromDeviceUidBytes)
        }
        this.downloadTimestamp = res.getLong(DOWNLOAD_TIMESTAMP)
        this.localDownloadTimestamp = res.getLong(LOCAL_DOWNLOAD_TIMESTAMP)
        this.hasExtendedPayload = res.getBoolean(HAS_EXTENDED_PAYLOAD)
        try {
            this.extendedPayloadKey =
                Encoded(res.getBytes(EXTENDED_PAYLOAD_KEY)).decodeSymmetricKey() as AuthEncKey?
        } catch (_: Exception) {
            this.extendedPayloadKey = null
        }
        this.extendedPayload = res.getBytes(EXTENDED_PAYLOAD)
        this.onHold = res.getBoolean(ON_HOLD)
    }

    @Throws(SQLException::class)
    override fun insert() {
        fetchManagerSession.session.prepareStatement(
            "InboxMessage.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES(?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, uid.bytes)
            statement.setBytes(3, wrappedKey!!.getBytes())
            statement.setBytes(4, encryptedContent!!.getBytes())
            statement.setBoolean(5, markedForDeletion)

            statement.setLong(6, serverTimestamp)
            statement.setBytes(7, payload)
            statement.setBytes(8, if (fromIdentity == null) null else fromIdentity!!.getBytes())
            statement.setLong(9, downloadTimestamp)
            statement.setLong(10, localDownloadTimestamp)

            statement.setBoolean(11, hasExtendedPayload)
            statement.setBytes(
                12,
                if (extendedPayloadKey == null) null else Encoded.of(extendedPayloadKey!!).bytes
            )
            statement.setBytes(13, extendedPayload)
            statement.setBytes(14, if (fromDeviceUid == null) null else fromDeviceUid!!.bytes)
            statement.setBoolean(15, onHold)

            statement.executeUpdate()
            this.commitHookBits = this.commitHookBits or HOOK_BIT_INSERT
            fetchManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        // before inserting a new deletedMessageUid, sometimes expunge all old entries
        if (System.currentTimeMillis() > lastExpungeTimestamp + DELETED_MESSAGE_RETENTION_TIME_MILLIS) {
            lastExpungeTimestamp = System.currentTimeMillis()
            try {
                val timestamp: Long =
                    System.currentTimeMillis() - DELETED_MESSAGE_RETENTION_TIME_MILLIS
                val toDelete: MutableList<IdentityAndUid?> = ArrayList<IdentityAndUid?>()
                for (entry in deletedMessageUids.entries) {
                    if (entry.value!! < timestamp) {
                        toDelete.add(entry.key)
                    }
                }
                Logger.d("Expunging " + toDelete.size + " deletedMessageUids")
                for (key in toDelete) {
                    deletedMessageUids.remove(key)
                }
            } catch (_: Exception) {
            }
        }

        deletedMessageUids[IdentityAndUid(ownedIdentity!!, uid)] = System.currentTimeMillis()

        // first, cascade delete the attachments, then delete the message itself.
        for (inboxAttachment in this.attachments!!) {
            try {
                inboxAttachment.deleteAttachmentFile()
            } catch (_: IOException) {
                throw SQLException("Error deleting attachment file.")
            }
            inboxAttachment.delete()
        }
        fetchManagerSession.session.prepareStatement(
            "InboxMessage.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
        }
    }

    // endregion
    // region hooks
    interface InboxMessageListener {
        fun messageWasDownloaded(networkReceivedMessage: NetworkReceivedMessage?)
        fun messageDecrypted(inboxMessage: InboxMessage?, attachments: Array<InboxAttachment>?)
    }

    interface ExtendedPayloadListener {
        fun messageHasExtendedPayloadToDownload(ownedIdentity: Identity?, uid: UID?)
        fun messageExtendedPayloadDownloaded(
            ownedIdentity: Identity?,
            uid: UID?,
            extendedPayload: ByteArray?
        )
    }

    interface MarkAsListedAndDeleteOnServerListener {
        fun messageCanBeMarkedAsListedOnServer(ownedIdentity: Identity?, messageUid: UID?, hasAttachments: Boolean)
        fun messageCanBeDeletedFromServer(ownedIdentity: Identity?, messageUid: UID?)
    }


    private var commitHookBits: Long = 0
    private var attachmentsToNotify: Array<InboxAttachment>? = null
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERT) != 0L) {
            fetchManagerSession.inboxMessageListener?.messageWasDownloaded(this.networkReceivedMessage)
        }
        if ((commitHookBits and HOOK_BIT_PAYLOAD_AND_FROM_IDENTITY_SET) != 0L) {
            if (fetchManagerSession.inboxMessageListener != null) {
                fetchManagerSession.inboxMessageListener.messageDecrypted(this, attachmentsToNotify)
                if (extendedPayloadKey != null && fetchManagerSession.extendedPayloadListener != null) {
                    fetchManagerSession.extendedPayloadListener.messageHasExtendedPayloadToDownload(
                        ownedIdentity,
                        uid
                    )
                }
            }
            // for application messages,
            // - we mark as listed on server if there are attachments
            // - we delete from server but not locally if there are none --> this way we do not rely on the app properly processing the message to avoid relisting
            fetchManagerSession.markAsListedAndDeleteOnServerListener?.messageCanBeMarkedAsListedOnServer(
                ownedIdentity,
                uid,
                !attachmentsToNotify.isNullOrEmpty()
            )
        }
        if ((commitHookBits and HOOK_BIT_EXTENDED_PAYLOAD_SET) != 0L) {
            fetchManagerSession.extendedPayloadListener?.messageExtendedPayloadDownloaded(
                ownedIdentity,
                uid,
                extendedPayload
            )
        }
        commitHookBits = 0
    } // endregion

    companion object {
        const val TABLE_NAME: String = "inbox_message"

        private const val DELETED_MESSAGE_RETENTION_TIME_MILLIS =
            600000L // keep deleted messages uids for 10 minutes
        private var lastExpungeTimestamp = System.currentTimeMillis()
        private val deletedMessageUids = HashMap<IdentityAndUid?, Long?>()

        const val OWNED_IDENTITY: String = "owned_identity"
        const val UID_: String = "uid"
        const val WRAPPED_KEY: String = "wrapped_key"
        const val ENCRYPTED_CONTENT: String = "encrypted_content"
        const val MARKED_FOR_DELETION: String = "marked_for_deletion"
        const val SERVER_TIMESTAMP: String = "server_timestamp"
        const val PAYLOAD: String = "payload"
        const val FROM_IDENTITY: String = "from_identity"
        const val DOWNLOAD_TIMESTAMP: String = "download_timestamp"
        const val LOCAL_DOWNLOAD_TIMESTAMP: String = "local_download_timestamp"
        const val HAS_EXTENDED_PAYLOAD: String = "has_extended_payload"
        const val EXTENDED_PAYLOAD_KEY: String = "extended_payload_key"
        const val EXTENDED_PAYLOAD: String = "extended_payload"
        const val FROM_DEVICE_UID: String = "from_device_uid"
        const val ON_HOLD: String = "on_hold"


        fun clearExtendedPayload(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity,
            messageUid: UID
        ) {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.clearExtendedPayload",
                    "UPDATE " + TABLE_NAME +
                            " SET " + HAS_EXTENDED_PAYLOAD + " = 0, " +
                            EXTENDED_PAYLOAD_KEY + " = NULL, " +
                            EXTENDED_PAYLOAD + " = NULL " +
                            "WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + UID_ + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, messageUid.bytes)
                    statement.executeUpdate()
                }
            } catch (_: SQLException) {
                // nothing
            }
        }


        // endregion
        // region constructors
        fun create(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?,
            encryptedContent: EncryptedBytes?,
            wrappedKey: EncryptedBytes?,
            serverTimestamp: Long,
            downloadTimestamp: Long,
            localDownloadTimestamp: Long,
            hasExtendedContent: Boolean
        ): InboxMessage? {
            if (messageUid == null || ownedIdentity == null || encryptedContent == null || wrappedKey == null) {
                return null
            }
            if (deletedMessageUids.containsKey(IdentityAndUid(ownedIdentity, messageUid))) {
                // we listed again a message that was deleted, just to be sure, create a pendingDelete
                fetchManagerSession.markAsListedAndDeleteOnServerListener?.messageCanBeDeletedFromServer(
                    ownedIdentity,
                    messageUid
                )
                return null
            }
            try {
                val inboxMessage = InboxMessage(
                    fetchManagerSession,
                    ownedIdentity,
                    messageUid,
                    encryptedContent,
                    wrappedKey,
                    serverTimestamp,
                    downloadTimestamp,
                    localDownloadTimestamp,
                    hasExtendedContent
                )
                inboxMessage.insert()
                return inboxMessage
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region getters
        fun get(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity,
            uid: UID?
        ): InboxMessage? {
            if (uid == null) {
                return null
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.get",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + UID_ + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, uid.bytes)
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return InboxMessage(fetchManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        fun exists(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity,
            uid: UID?
        ): Boolean {
            if (uid == null) {
                return false
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.exists",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + UID_ + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, uid.bytes)
                    statement.executeQuery().use { res ->
                        return res.next()
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return false
            }
        }

        @Throws(SQLException::class)
        fun getAllForOwnedIdentity(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity
        ): Array<InboxMessage> {
            fetchManagerSession.session.prepareStatement(
                "InboxMessage.getAllForOwnedIdentity",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<InboxMessage> = ArrayList()
                    while (res.next()) {
                        list.add(InboxMessage(fetchManagerSession, res))
                    }
                    return list.toTypedArray<InboxMessage>()
                }
            }
        }


        // this method only returns truly unprocessed messages, not PreKey messages without a contact
        @Throws(SQLException::class)
        fun getUnprocessedMessagesForOwnedIdentity(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity
        ): Array<InboxMessage> {
            fetchManagerSession.session.prepareStatement(
                "InboxMessage.getUnprocessedMessagesForOwnedIdentity",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ?" +
                        " AND " + PAYLOAD + " IS NULL " +
                        " AND " + FROM_IDENTITY + " IS NULL " +
                        " AND " + MARKED_FOR_DELETION + " = 0" +
                        " ORDER BY " + SERVER_TIMESTAMP + " ASC;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<InboxMessage> = ArrayList()
                    while (res.next()) {
                        list.add(InboxMessage(fetchManagerSession, res))
                    }
                    return list.toTypedArray<InboxMessage>()
                }
            }
        }

        // this method return unprocessed messages, but also PreKey messages where the contact was not yet a contact
        fun getUnprocessedMessages(fetchManagerSession: FetchManagerSession): Array<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getUnprocessedMessages",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + PAYLOAD + " IS NULL " +
                            " AND " + MARKED_FOR_DELETION + " = 0" +
                            " ORDER BY " + SERVER_TIMESTAMP + " ASC;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxMessage>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getPendingPreKeyMessages(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): MutableList<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getPendingPreKeyMessages",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + PAYLOAD + " IS NULL " +
                            " AND " + OWNED_IDENTITY + " = ? " +
                            " AND " + FROM_IDENTITY + " = ? " +
                            " AND " + MARKED_FOR_DELETION + " = 0 " +
                            " ORDER BY " + SERVER_TIMESTAMP + " ASC;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, contactIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list
                    }
                }
            } catch (_: SQLException) {
                return mutableListOf()
            }
        }

        fun getExpiredPendingPreKeyMessages(
            fetchManagerSession: FetchManagerSession,
            timestamp: Long
        ): MutableList<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getExpiredPendingPreKeyMessages",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + PAYLOAD + " IS NULL " +
                            " AND " + FROM_IDENTITY + " IS NOT NULL " +
                            " AND " + LOCAL_DOWNLOAD_TIMESTAMP + " < ?;"
                ).use { statement ->
                    statement.setLong(1, timestamp)
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list
                    }
                }
            } catch (_: SQLException) {
                return mutableListOf()
            }
        }

        fun getDecryptedMessages(fetchManagerSession: FetchManagerSession): Array<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getDecryptedMessages",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + PAYLOAD + " NOT NULL " +
                            " AND " + MARKED_FOR_DELETION + " = 0" +
                            " AND " + ON_HOLD + " = 0" +
                            " ORDER BY " + SERVER_TIMESTAMP + " ASC;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxMessage>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getMarkedForDeletionMessages(fetchManagerSession: FetchManagerSession): Array<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getMarkedForDeletionMessages",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + MARKED_FOR_DELETION + " = 1;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxMessage>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getExtendedPayloadMessages(fetchManagerSession: FetchManagerSession): Array<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getExtendedPayloadMessages",

                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + EXTENDED_PAYLOAD + " IS NOT NULL;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxMessage>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getMissingExtendedPayloadMessages(fetchManagerSession: FetchManagerSession): Array<InboxMessage> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxMessage.getMissingExtendedPayloadMessages",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + EXTENDED_PAYLOAD_KEY + " IS NOT NULL" +
                            " AND " + EXTENDED_PAYLOAD + " IS NULL;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxMessage> = ArrayList()
                        while (res.next()) {
                            list.add(InboxMessage(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxMessage>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            UID_ + " BLOB NOT NULL, " +
                            WRAPPED_KEY + " BLOB NOT NULL, " +
                            ENCRYPTED_CONTENT + " BLOB NOT NULL, " +
                            MARKED_FOR_DELETION + " BIT NOT NULL, " +
                            SERVER_TIMESTAMP + " BIGINT NOT NULL, " +
                            PAYLOAD + " BLOB, " +
                            FROM_IDENTITY + " BLOB, " +
                            DOWNLOAD_TIMESTAMP + " BIGINT NOT NULL, " +
                            LOCAL_DOWNLOAD_TIMESTAMP + " BIGINT NOT NULL, " +
                            HAS_EXTENDED_PAYLOAD + " BIT NOT NULL, " +
                            EXTENDED_PAYLOAD_KEY + " BLOB, " +
                            EXTENDED_PAYLOAD + " BLOB, " +
                            FROM_DEVICE_UID + " BLOB, " +
                            ON_HOLD + " BIT NOT NULL, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + UID_ + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 2 && newVersion >= 2) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 2")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE `inbox_message` ADD COLUMN `server_timestamp` BIGINT NOT NULL DEFAULT 0")
                }
                oldVersion = 2
            }
            if (oldVersion < 4 && newVersion >= 4) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 4\n!!!! THIS MIGRATION IS DESTRUCTIVE !!!!")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE IF EXISTS `inbox_message`;")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS inbox_message (" +
                                "uid BLOB PRIMARY KEY, " +
                                "to_identity BLOB NOT NULL, " +
                                "wrapped_key BLOB NOT NULL, " +
                                "encrypted_content BLOB NOT NULL, " +
                                "marked_for_deletion BIT NOT NULL, " +
                                "server_timestamp BIGINT NOT NULL, " +
                                "payload BLOB, " +
                                "from_identity BLOB);"
                    )
                }
                oldVersion = 4
            }
            if (oldVersion < 15 && newVersion >= 15) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 15")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message RENAME TO old_inbox_message")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS inbox_message (" +
                                " owned_identity BLOB NOT NULL, " +
                                " uid BLOB NOT NULL, " +
                                " wrapped_key BLOB NOT NULL, " +
                                " encrypted_content BLOB NOT NULL, " +
                                " marked_for_deletion BIT NOT NULL, " +
                                " server_timestamp BIGINT NOT NULL, " +
                                " payload BLOB, " +
                                " from_identity BLOB, " +
                                " CONSTRAINT PK_inbox_message PRIMARY KEY(owned_identity, uid));"
                    )
                    statement.execute("INSERT INTO inbox_message SELECT to_identity, uid, wrapped_key, encrypted_content, marked_for_deletion, server_timestamp, payload, from_identity FROM old_inbox_message")
                    statement.execute("DROP TABLE old_inbox_message")
                }
                oldVersion = 15
            }
            if (oldVersion < 17 && newVersion >= 17) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 17")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message RENAME TO old_inbox_message")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS inbox_message (" +
                                " owned_identity BLOB NOT NULL, " +
                                " uid BLOB NOT NULL, " +
                                " wrapped_key BLOB NOT NULL, " +
                                " encrypted_content BLOB NOT NULL, " +
                                " marked_for_deletion BIT NOT NULL, " +
                                " server_timestamp BIGINT NOT NULL, " +
                                " payload BLOB, " +
                                " from_identity BLOB, " +
                                " download_timestamp BIGINT NOT NULL, " +
                                " CONSTRAINT PK_inbox_message PRIMARY KEY(owned_identity, uid));"
                    )
                    statement.execute("INSERT INTO inbox_message SELECT owned_identity, uid, wrapped_key, encrypted_content, marked_for_deletion, server_timestamp, payload, from_identity, server_timestamp FROM old_inbox_message")
                    statement.execute("DROP TABLE old_inbox_message")
                }
                oldVersion = 17
            }
            if (oldVersion < 19 && newVersion >= 19) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 19")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `local_download_timestamp` BIGINT NOT NULL DEFAULT 0")
                }
                oldVersion = 19
            }
            if (oldVersion < 22 && newVersion >= 22) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 22")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `has_extended_payload` BIT NOT NULL DEFAULT 0")
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `extended_payload_key` BLOB DEFAULT NULL")
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `extended_payload` BLOB DEFAULT NULL")
                }
                oldVersion = 22
            }
            if (oldVersion < 38 && newVersion >= 38) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 38")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `marked_as_listed_on_server` BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 38
            }
            if (oldVersion < 40 && newVersion >= 40) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 40")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message DROP COLUMN `marked_as_listed_on_server`")
                }
                oldVersion = 40
            }
            if (oldVersion < 43 && newVersion >= 43) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 43")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `from_device_uid` BLOB DEFAULT NULL")
                }
                oldVersion = 43
            }
            if (oldVersion < 45 && newVersion >= 45) {
                Logger.d("MIGRATING `inbox_message` DATABASE FROM VERSION " + oldVersion + " TO 45")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_message ADD COLUMN `on_hold` BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 45
            }
        }


        private const val HOOK_BIT_INSERT: Long = 0x1
        private const val HOOK_BIT_PAYLOAD_AND_FROM_IDENTITY_SET: Long = 0x2
        private const val HOOK_BIT_EXTENDED_PAYLOAD_SET: Long = 0x4
    }
}
