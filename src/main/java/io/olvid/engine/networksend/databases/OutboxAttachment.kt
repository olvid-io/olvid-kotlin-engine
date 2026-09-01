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
package io.olvid.engine.networksend.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Chunk.Companion.lengthOfEncodedChunkFromLengthOfInnerData
import io.olvid.engine.datatypes.Chunk.Companion.lengthOfInnerDataFromLengthOfEncodedChunk
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networksend.datatypes.SendManagerSession
import java.sql.ResultSet
import java.sql.SQLException
import java.util.regex.Pattern


class OutboxAttachment : ObvDatabase {
    private val sendManagerSession: SendManagerSession

    private var ownedIdentity: Identity? = null
    @JvmField val messageUid: UID
    @JvmField val attachmentNumber: Int
    @JvmField val url: String? // this is a relative path to the attachment file
    private val deleteAfterSend: Boolean
    @JvmField val attachmentLength: Long
    var key: AuthEncKey? = null
        private set
    private var acknowledgedChunkCount: Int
    var isAcknowledged: Boolean
        private set
    @JvmField val ciphertextChunkLength: Int
    var isCancelExternallyRequested: Boolean
        private set
    private var chunkUploadPrivateUrls: String?
    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun shouldBeDeletedAfterSend(): Boolean {
        return deleteAfterSend
    }

    fun getAcknowledgedChunkCount(): Int {
        return acknowledgedChunkCount
    }

    fun getChunkUploadPrivateUrls(): Array<String?> {
        if (chunkUploadPrivateUrls == null) {
            return arrayOfNulls<String>(0)
        }
        return chunkUploadPrivateUrls!!.split("¦".toRegex()).toTypedArray()
    }

    private var attachmentChunkLength = 0

    val cleartextChunkLength: Int
        get() {
            if (attachmentChunkLength == 0) {
                val authEnc = Suite.getAuthEnc(key)!!
                attachmentChunkLength =
                    lengthOfInnerDataFromLengthOfEncodedChunk(
                        authEnc.plaintextLengthFromCiphertextLength(ciphertextChunkLength)
                    )
            }
            return attachmentChunkLength
        }

    var numberOfChunks: Int = 0
        get() {
            if (field == 0) {
                field = 1 + (((attachmentLength - 1) / this.cleartextChunkLength)).toInt()
            }
            return field
        }
        private set

    var ciphertextLength: Long = 0
        get() {
            if (field == 0L) {
                val authEnc = Suite.getAuthEnc(key)!!
                val lastChunkLength =
                    (attachmentLength - (this.numberOfChunks - 1) * (this.cleartextChunkLength.toLong())).toInt()
                // the ciphertext is a number of full chunks, plus the encrypted length of the lastChunk
                field =
                    (this.numberOfChunks - 1) * (ciphertextChunkLength.toLong()) + authEnc.ciphertextLengthFromPlaintextLength(
                        lengthOfEncodedChunkFromLengthOfInnerData(
                            lastChunkLength
                        )
                    )
            }
            return field
        }
        private set

    val remainingByteCountToSend: Long
        get() {
            val remaining =
                this.ciphertextLength - (ciphertextChunkLength.toLong()) * acknowledgedChunkCount
            if (remaining < 0) {
                return 0
            } else {
                return remaining
            }
        }

    val priority: Long
        get() = this.remainingByteCountToSend

    // endregion
    // region setters
    @Throws(SQLException::class)
    fun setCancelExternallyRequested() {
        sendManagerSession.session.prepareStatement(
            "OutboxAttachment.setCancelExternallyRequested",
            "UPDATE " + TABLE_NAME + " SET " +
                    CANCEL_EXTERNALLY_REQUESTED + " = 1 " +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + MESSAGE_UID + " = ? " +
                    " AND " + ATTACHMENT_NUMBER + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setInt(3, attachmentNumber)
            statement.executeUpdate()
            this.isCancelExternallyRequested = true
            commitHookBits = commitHookBits or HOOK_BIT_CANCEL_REQUESTED
            sendManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setCancelProcessed() {
        sendManagerSession.session.prepareStatement(
            "OutboxAttachment.setCancelProcessed",
            "UPDATE " + TABLE_NAME + " SET " +
                    ACKNOWLEDGED + " = 1 " +
                    " WHERE " + CANCEL_EXTERNALLY_REQUESTED + " = 1 " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + MESSAGE_UID + " = ? " +
                    " AND " + ATTACHMENT_NUMBER + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setInt(3, attachmentNumber)
            statement.executeUpdate()
            this.isAcknowledged = true
        }
    }


    fun setAcknowledgedChunkCount(acknowledgedChunkCount: Int) {
        if (acknowledgedChunkCount < this.acknowledgedChunkCount) {
            return
        }

        var sqlQueryString = "UPDATE " + TABLE_NAME + " SET "
        if (acknowledgedChunkCount > this.acknowledgedChunkCount) {
            commitHookBits = commitHookBits or HOOK_BIT_PROGRESS
            sendManagerSession.session.addSessionCommitListener(this)
        }
        if (acknowledgedChunkCount == this.numberOfChunks) {
            sqlQueryString += ACKNOWLEDGED + " = 1, "
            commitHookBits = commitHookBits or HOOK_BIT_FINISHED
            sendManagerSession.session.addSessionCommitListener(this)
        }
        sqlQueryString += ACKNOWLEDGED_CHUNK_COUNT + " = ? " +
                " WHERE " + OWNED_IDENTITY + " = ? " +
                " AND " + MESSAGE_UID + " = ? " +
                " AND " + ATTACHMENT_NUMBER + " = ?;"

        try {
            sendManagerSession.session.prepareStatement(
                "OutboxAttachment.setAcknowledgedChunkCount",
                sqlQueryString
            ).use { statement ->
                statement.setLong(1, acknowledgedChunkCount.toLong())
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setBytes(3, messageUid.bytes)
                statement.setInt(4, attachmentNumber)
                statement.executeUpdate()
                if (acknowledgedChunkCount == this.numberOfChunks) {
                    this.isAcknowledged = true
                }
                this.acknowledgedChunkCount = acknowledgedChunkCount
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    fun setChunkUploadPrivateUrls(chunkUploadPrivateUrls: Array<String?>?) {
        val serialized: String?
        if (chunkUploadPrivateUrls == null || chunkUploadPrivateUrls.size == 0) {
            serialized = null
        } else {
            val sb = StringBuilder()
            var first = true
            for (chunkUploadPrivateUrl in chunkUploadPrivateUrls) {
                if (!first) {
                    sb.append("¦")
                }
                first = false
                sb.append(chunkUploadPrivateUrl)
            }
            serialized = sb.toString()
        }
        try {
            sendManagerSession.session.prepareStatement(
                "OutboxAttachment.setChunkUploadPrivateUrls",
                "UPDATE " + TABLE_NAME + " SET " + CHUNK_UPLOAD_PRIVATE_URLS + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ? " +
                        " AND " + ATTACHMENT_NUMBER + " = ?;"
            ).use { statement ->
                statement.setString(1, serialized)
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setBytes(3, messageUid.bytes)
                statement.setInt(4, attachmentNumber)
                statement.executeUpdate()
                this.chunkUploadPrivateUrls = serialized
            }
        } catch (_: SQLException) {
        }
    }

    private constructor(
        sendManagerSession: SendManagerSession,
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int,
        url: String?,
        deleteAfterSend: Boolean,
        attachmentLength: Long,
        key: AuthEncKey?
    ) {
        this.sendManagerSession = sendManagerSession
        this.ownedIdentity = ownedIdentity
        this.messageUid = messageUid
        this.attachmentNumber = attachmentNumber
        this.url = url
        this.deleteAfterSend = deleteAfterSend
        this.attachmentLength = attachmentLength
        this.key = key
        this.acknowledgedChunkCount = 0
        this.isAcknowledged = false
        this.ciphertextChunkLength = Math.min(Integer.MAX_VALUE.toLong(), Math.max(attachmentLength / 100 + 41, Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH.toLong())).toInt() // the + 41 is here to compensate for encryption overhead
        this.isCancelExternallyRequested = false
        this.chunkUploadPrivateUrls = null
    }

    private constructor(sendManagerSession: SendManagerSession, res: ResultSet) {
        this.sendManagerSession = sendManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.messageUid = UID(res.getBytes(MESSAGE_UID))
        this.attachmentNumber = res.getInt(ATTACHMENT_NUMBER)
        this.url = res.getString(URL)
        this.deleteAfterSend = res.getBoolean(DELETE_AFTER_SEND)
        this.attachmentLength = res.getLong(ATTACHMENT_LENGTH)
        try {
            this.key = Encoded(res.getBytes(KEY)).decodeSymmetricKey() as AuthEncKey?
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.acknowledgedChunkCount = res.getInt(ACKNOWLEDGED_CHUNK_COUNT)
        this.isAcknowledged = res.getBoolean(ACKNOWLEDGED)
        this.ciphertextChunkLength = res.getInt(CIPHERTEXT_CHUNK_LENGTH)
        this.isCancelExternallyRequested = res.getBoolean(CANCEL_EXTERNALLY_REQUESTED)
        this.chunkUploadPrivateUrls = res.getString(CHUNK_UPLOAD_PRIVATE_URLS)
    }

    @Throws(SQLException::class)
    override fun insert() {
        sendManagerSession.session.prepareStatement(
            "OutboxAttachment.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setInt(3, attachmentNumber)
            statement.setString(4, url)
            statement.setBoolean(5, deleteAfterSend)

            statement.setLong(6, attachmentLength)
            statement.setBytes(7, Encoded.of(key!!).bytes)
            statement.setInt(8, acknowledgedChunkCount)
            statement.setBoolean(9, this.isAcknowledged)
            statement.setInt(10, ciphertextChunkLength)

            statement.setBoolean(11, this.isCancelExternallyRequested)
            statement.setString(12, chunkUploadPrivateUrls)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        sendManagerSession.session.prepareStatement(
            "OutboxAttachment.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + MESSAGE_UID + " = ? " +
                    " AND " + ATTACHMENT_NUMBER + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setInt(3, attachmentNumber)
            statement.executeUpdate()
        }
    }

    // endregion
    interface OutboxAttachmentCanBeSentListener {
        fun outboxAttachmentCanBeSent(
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int,
            initialPriority: Long
        )
    }

    interface OutboxAttachmentCancelRequestedListener {
        fun outboxAttachmentCancelRequested(
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int
        )
    }

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_FINISHED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED_OWNED_IDENTITY_KEY] = ownedIdentity!!
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED_MESSAGE_UID_KEY] = messageUid
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED_ATTACHMENT_NUMBER_KEY] = attachmentNumber
            sendManagerSession.notificationPostingDelegate?.postNotification(
                UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED,
                userInfo
            )
        } else if ((commitHookBits and HOOK_BIT_PROGRESS) != 0L) { // Only send a progress notification when upload is not finished
            val userInfo = HashMap<String, Any>()
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_OWNED_IDENTITY_KEY] = ownedIdentity!!
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_MESSAGE_UID_KEY] = messageUid
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY] = attachmentNumber
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_PROGRESS_KEY] = (acknowledgedChunkCount.toFloat() * ciphertextChunkLength) / this.ciphertextLength
            sendManagerSession.notificationPostingDelegate?.postNotification(
                UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS,
                userInfo
            )
        } else if ((commitHookBits and HOOK_BIT_CANCEL_REQUESTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED_OWNED_IDENTITY_KEY] = ownedIdentity!!
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED_MESSAGE_UID_KEY] = messageUid
            userInfo[UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED_ATTACHMENT_NUMBER_KEY] = attachmentNumber
            sendManagerSession.notificationPostingDelegate?.postNotification(
                UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED,
                userInfo
            )
            sendManagerSession.outboxAttachmentCancelRequestedListener?.outboxAttachmentCancelRequested(
                ownedIdentity,
                messageUid,
                attachmentNumber
            )
        }
        commitHookBits = 0
    }

    fun messageIsAcknowledged() {
        if (!this.isAcknowledged) {
            if (this.isCancelExternallyRequested) {
                sendManagerSession.outboxAttachmentCancelRequestedListener?.outboxAttachmentCancelRequested(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            } else {
                sendManagerSession.outboxAttachmentCanBeSentListener?.outboxAttachmentCanBeSent(
                    ownedIdentity, messageUid, attachmentNumber,
                    this.priority
                )
            }
        }
    }

    companion object {
        const val TABLE_NAME: String = "outbox_attachment"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val MESSAGE_UID: String = "message_uid"
        const val ATTACHMENT_NUMBER: String = "attachment_number"
        const val URL: String = "url"
        const val DELETE_AFTER_SEND: String = "delete_after_send"
        const val ATTACHMENT_LENGTH: String = "attachment_length"
        const val KEY: String = "key"
        const val ACKNOWLEDGED_CHUNK_COUNT: String = "acknowledged_chunk_count"
        const val ACKNOWLEDGED: String = "acknowledged"
        const val CIPHERTEXT_CHUNK_LENGTH: String = "ciphertext_chunk_length"
        const val CANCEL_EXTERNALLY_REQUESTED: String = "cancel_externally_requested"
        const val CHUNK_UPLOAD_PRIVATE_URLS: String = "chunk_upload_private_urls"

        // region computed properties
        fun computeUniqueUid(ownedIdentity: Identity, messageUid: UID, attachmentNumber: Int): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            val input =
                ByteArray(ownedIdentity.getBytes().size + UID.UID_LENGTH + Encoded.INT_ENCODING_LENGTH + Encoded.ENCODED_HEADER_LENGTH)
            System.arraycopy(ownedIdentity.getBytes(), 0, input, 0, ownedIdentity.getBytes().size)
            System.arraycopy(
                messageUid.bytes,
                0,
                input,
                ownedIdentity.getBytes().size,
                UID.UID_LENGTH
            )
            System.arraycopy(
                Encoded.of(attachmentNumber.toLong()).bytes,
                0,
                input,
                ownedIdentity.getBytes().size + UID.UID_LENGTH,
                Encoded.INT_ENCODING_LENGTH + Encoded.ENCODED_HEADER_LENGTH
            )
            return UID(sha256.digest(input))
        }

        // endregion
        // region constructors
        fun create(
            session: SendManagerSession?,
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int,
            url: String?,
            deleteAfterSend: Boolean,
            attachmentLength: Long,
            key: AuthEncKey?
        ): OutboxAttachment? {
            if (ownedIdentity == null || messageUid == null || url == null || key == null) {
                return null
            }
            try {
                val outboxAttachment = OutboxAttachment(
                    session!!,
                    ownedIdentity,
                    messageUid,
                    attachmentNumber,
                    url,
                    deleteAfterSend,
                    attachmentLength,
                    key
                )
                outboxAttachment.insert()
                return outboxAttachment
            } catch (e: SQLException) {
                Logger.x(e)
                return null
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
                            MESSAGE_UID + " BLOB NOT NULL, " +
                            ATTACHMENT_NUMBER + " INT NOT NULL, " +
                            URL + " TEXT NOT NULL, " +
                            DELETE_AFTER_SEND + " BIT NOT NULL, " +
                            ATTACHMENT_LENGTH + " BIGINT NOT NULL, " +
                            KEY + " BLOB NOT NULL, " +
                            ACKNOWLEDGED_CHUNK_COUNT + " INT NOT NULL, " +
                            ACKNOWLEDGED + " BIT NOT NULL, " +
                            CIPHERTEXT_CHUNK_LENGTH + " INT NOT NULL, " +
                            CANCEL_EXTERNALLY_REQUESTED + " BIT NOT NULL, " +
                            CHUNK_UPLOAD_PRIVATE_URLS + " TEXT, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + MESSAGE_UID + ", " + ATTACHMENT_NUMBER + "), " +
                            "FOREIGN KEY (" + OWNED_IDENTITY + ", " + MESSAGE_UID + ") REFERENCES " + OutboxMessage.TABLE_NAME + "(" + OutboxMessage.OWNED_IDENTITY + ", " + OutboxMessage.UID_ + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 13 && newVersion >= 13) {
                Logger.d("MIGRATING `outbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 13")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_attachment ADD COLUMN chunk_upload_private_urls TEXT DEFAULT NULL;")
                }
                oldVersion = 13
            }
            if (oldVersion < 15 && newVersion >= 15) {
                Logger.d("MIGRATING `outbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 15")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_attachment RENAME TO old_outbox_attachment")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS outbox_attachment (" +
                                "owned_identity BLOB NOT NULL, " +
                                "message_uid BLOB NOT NULL, " +
                                "attachment_number INT NOT NULL, " +
                                "url TEXT NOT NULL, " +
                                "delete_after_send BIT NOT NULL, " +
                                "attachment_length BIGINT NOT NULL, " +
                                "key BLOB NOT NULL, " +
                                "acknowledged_chunk_count INT NOT NULL, " +
                                "acknowledged BIT NOT NULL, " +
                                "ciphertext_chunk_length INT NOT NULL, " +
                                "cancel_externally_requested BIT NOT NULL, " +
                                "chunk_upload_private_urls TEXT, " +
                                "CONSTRAINT PK_outbox_attachment PRIMARY KEY(owned_identity, message_uid, attachment_number), " +
                                "FOREIGN KEY (owned_identity, message_uid) REFERENCES outbox_message(owned_identity, uid));"
                    )
                    statement.execute(
                        "INSERT INTO outbox_attachment SELECT i.identity, a.message_uid, a.attachment_number, a.url, a.delete_after_send, a.attachment_length, a.key, a.acknowledged_chunk_count, a.acknowledged, a.ciphertext_chunk_length, a.cancel_externally_requested, a.chunk_upload_private_urls FROM old_outbox_attachment AS a" +
                                " CROSS JOIN owned_identity AS i"
                    )
                    statement.execute("DROP TABLE old_outbox_attachment")
                }
                oldVersion = 15
            }
            if (oldVersion < 16 && newVersion >= 16) {
                Logger.d("MIGRATING `outbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 16")
                val pattern = Pattern.compile("^.*/(fyles/[0-9A-F]+$)")
                session.createStatement().use { statement ->
                    session.prepareStatement(
                        "UPDATE outbox_attachment " +
                                " SET url = ? " +
                                " WHERE owned_identity = ? " +
                                " AND message_uid = ? " +
                                " AND attachment_number = ?"
                    ).use { updateStatement ->
                        statement.executeQuery("SELECT * FROM outbox_attachment").use { res ->
                            while (res.next()) {
                                val oldUrl = res.getString("url")
                                val m = pattern.matcher(oldUrl)
                                var newUrl: String? = ""
                                if (m.find()) {
                                    newUrl = m.group(1)
                                }
                                updateStatement.setString(1, newUrl)
                                updateStatement.setBytes(2, res.getBytes("owned_identity"))
                                updateStatement.setBytes(3, res.getBytes("message_uid"))
                                updateStatement.setInt(4, res.getInt("attachment_number"))
                                updateStatement.executeUpdate()
                            }
                        }
                    }
                }
                oldVersion = 16
            }
        }

        @Throws(SQLException::class)
        fun deleteAll(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity,
            messageUid: UID
        ) {
            sendManagerSession.session.prepareStatement(
                "OutboxAttachment.deleteAll",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, messageUid.bytes)
                statement.executeUpdate()
            }
        }

        // endregion
        // region getters
        fun getAll(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?
        ): Array<OutboxAttachment?>? {
            if (ownedIdentity == null || messageUid == null) {
                return null
            }
            try {
                sendManagerSession.session.prepareStatement(
                    "OutboxAttachment.getAll",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + MESSAGE_UID + " = ? " +
                            " ORDER BY " + ATTACHMENT_NUMBER + " ASC;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, messageUid.bytes)
                    statement.executeQuery().use { res ->
                        val list: MutableList<OutboxAttachment?> = ArrayList<OutboxAttachment?>()
                        while (res.next()) {
                            list.add(OutboxAttachment(sendManagerSession, res))
                        }
                        return list.toTypedArray<OutboxAttachment?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<OutboxAttachment>(0)
            }
        }

        @Throws(SQLException::class)
        fun get(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int
        ): OutboxAttachment? {
            if (ownedIdentity == null || messageUid == null) {
                return null
            }
            sendManagerSession.session.prepareStatement(
                "OutboxAttachment.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ? " +
                        " AND " + ATTACHMENT_NUMBER + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, messageUid.bytes)
                statement.setInt(3, attachmentNumber)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OutboxAttachment(sendManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        fun getAllToCancel(sendManagerSession: SendManagerSession): Array<OutboxAttachment?> {
            try {
                sendManagerSession.session.prepareStatement(
                    "OutboxAttachment.getAllToCancel",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + CANCEL_EXTERNALLY_REQUESTED + " = 1 " +
                            " AND " + ACKNOWLEDGED + " = 0"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<OutboxAttachment?> = ArrayList<OutboxAttachment?>()
                        while (res.next()) {
                            list.add(OutboxAttachment(sendManagerSession, res))
                        }
                        return list.toTypedArray<OutboxAttachment?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<OutboxAttachment>(0)
            }
        }

        private const val HOOK_BIT_PROGRESS: Long = 0x1
        private const val HOOK_BIT_FINISHED: Long = 0x2
        private const val HOOK_BIT_CANCEL_REQUESTED: Long = 0x4
    }
}
