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
import io.olvid.engine.datatypes.Chunk.Companion.lengthOfInnerDataFromLengthOfEncodedChunk
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.datatypes.DownloadAttachmentPriorityCategory
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import io.olvid.engine.storage.EngineWriteMode
import java.io.File
import java.io.IOException
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types
import kotlin.collections.toTypedArray

class InboxAttachment : ObvDatabase {
    private val fetchManagerSession: FetchManagerSession

    private var ownedIdentity: Identity? = null
    @JvmField val messageUid: UID
    @JvmField val attachmentNumber: Int
    @JvmField val expectedLength: Long
    @JvmField val chunkLength: Int
    var metadata: ByteArray?
        private set
    var key: AuthEncKey? = null
        private set
    var fileSize: Long
        private set
    var receivedLength: Long
        private set
    var priorityCategory: Int?
        private set
    var isDownloadRequested: Boolean
        private set
    var timestampOfFetchRequest: Long?
        private set
    var isMarkedForDeletion: Boolean
        private set
    private var chunkDownloadPrivateUrls: String?
    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    val isUploadCancelledBySender: Boolean
        get() = UPLOAD_CANCELLED_CHUNK_URLS == chunkDownloadPrivateUrls

    fun getChunkDownloadPrivateUrls(): Array<String?> {
        if (chunkDownloadPrivateUrls == null || isUploadCancelledBySender) {
            return emptyArray()
        }
        return chunkDownloadPrivateUrls!!.split("¦".toRegex()).toTypedArray()
    }


    fun cannotBeFetched(): Boolean {
        return key == null
    }

    val plaintextExpectedLength: Long
        get() {
            val authEnc = Suite.getDefaultAuthEnc(0)
            val fullChunkCount = (expectedLength - 1) / chunkLength
            return lengthOfInnerDataFromLengthOfEncodedChunk(
                authEnc.plaintextLengthFromCiphertextLength(
                    chunkLength
                )
            ) * fullChunkCount +
                    lengthOfInnerDataFromLengthOfEncodedChunk(
                        authEnc.plaintextLengthFromCiphertextLength((expectedLength - fullChunkCount * chunkLength).toInt())
                    )
        }

    val plaintextReceivedLength: Long
        get() {
            val authEnc = Suite.getDefaultAuthEnc(0)
            val fullChunkCount = (receivedLength - 1) / chunkLength
            return lengthOfInnerDataFromLengthOfEncodedChunk(
                authEnc.plaintextLengthFromCiphertextLength(
                    chunkLength
                )
            ) * fullChunkCount +
                    lengthOfInnerDataFromLengthOfEncodedChunk(
                        authEnc.plaintextLengthFromCiphertextLength((receivedLength - fullChunkCount * chunkLength).toInt())
                    )
        }

    val priority: Long
        get() {
            when (priorityCategory) {
                DownloadAttachmentPriorityCategory.WEIGHT -> return expectedLength - receivedLength
                DownloadAttachmentPriorityCategory.TIMESTAMP -> return -timestampOfFetchRequest!!
                else -> return 0
            }
        }

    val receivedChunkCount: Int
        get() {
            if (receivedLength == expectedLength) {
                return 1 + ((receivedLength - 1) / chunkLength).toInt()
            } else {
                return (receivedLength / chunkLength).toInt()
            }
        }

    val progress: Float
        get() = (receivedLength.toFloat()) / expectedLength

    val message: InboxMessage?
        get() = ownedIdentity?.let { InboxMessage.get(fetchManagerSession, it, messageUid) }

    // endregion
    // region setters
    fun requestDownload(priorityCategory: Int) {
        try {
            fetchManagerSession.session.prepareStatement(
                "InboxAttachment.requestDownload",
                "UPDATE " + TABLE_NAME +
                        " SET " + DOWNLOAD_REQUESTED + " = 1, " +
                        PRIORITY_CATEGORY + " = ?, " +
                        TIMESTAMP_OF_FETCH_REQUEST + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ? " +
                        " AND " + ATTACHMENT_NUMBER + " = ?;"
            ).use { statement ->
                statement.setInt(1, priorityCategory)
                val timestamp = System.currentTimeMillis()
                statement.setLong(2, timestamp)
                statement.setBytes(3, ownedIdentity!!.getBytes())
                statement.setBytes(4, messageUid.bytes)
                statement.setInt(5, attachmentNumber)
                statement.executeUpdate()
                this.isDownloadRequested = true
                this.priorityCategory = priorityCategory
                this.timestampOfFetchRequest = timestamp
                commitHookBits = commitHookBits or HOOK_BIT_DOWNLOAD_REQUESTED
                fetchManagerSession.session.addSessionCommitListener(this)
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    fun pauseDownload() {
        try {
            fetchManagerSession.session.prepareStatement(
                "InboxAttachment.pauseDownload",
                "UPDATE " + TABLE_NAME +
                        " SET " + DOWNLOAD_REQUESTED + " = 0 " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ? " +
                        " AND " + ATTACHMENT_NUMBER + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity!!.getBytes())
                statement.setBytes(2, messageUid.bytes)
                statement.setInt(3, attachmentNumber)
                statement.executeUpdate()
                this.isDownloadRequested = false
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    fun markForDeletion() {
        try {
            fetchManagerSession.session.prepareStatement(
                "InboxAttachment.markForDeletion",
                "UPDATE " + TABLE_NAME + " SET " +
                        MARKED_FOR_DELETION + " = 1 " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ? " +
                        " AND " + ATTACHMENT_NUMBER + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity!!.getBytes())
                statement.setBytes(2, messageUid.bytes)
                statement.setInt(3, attachmentNumber)
                statement.executeUpdate()
                this.isMarkedForDeletion = true
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }


    @Throws(Exception::class)
    fun setKeyAndMetadata(key: AuthEncKey, metadata: ByteArray) {
        if (this.key != null || this.metadata != null) {
            throw Exception("Attachment key and metadata were already set.")
        }
        fetchManagerSession.session.prepareStatement(
            "InboxAttachment.setKeyAndMetadata",
            "UPDATE " + TABLE_NAME +
                    " SET " + KEY + " = ?, " + METADATA + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + MESSAGE_UID + " = ? " +
                    " AND " + ATTACHMENT_NUMBER + " = ?;"
        ).use { statement ->
            statement.setBytes(1, Encoded.of(key).bytes)
            statement.setBytes(2, metadata)
            statement.setBytes(3, ownedIdentity!!.getBytes())
            statement.setBytes(4, messageUid.bytes)
            statement.setInt(5, attachmentNumber)
            statement.executeUpdate()
            this.key = key
            this.metadata = metadata
        }
    }

    @Throws(Exception::class)
    fun setChunkDownloadPrivateUrls(chunkDownloadPrivateUrls: Array<String?>) {
        require(chunkDownloadPrivateUrls.isNotEmpty())

        val sb = StringBuilder()
        var first = true
        for (chunkDownloadPrivateUrl in chunkDownloadPrivateUrls) {
            if (!first) {
                sb.append("¦")
            }
            first = false
            sb.append(chunkDownloadPrivateUrl)
        }
        val serialized = sb.toString()

        fetchManagerSession.session.prepareStatement(
            "InboxAttachment.setChunkDownloadPrivateUrls",
            "UPDATE " + TABLE_NAME +
                    " SET " + CHUNK_DOWNLOAD_PRIVATE_URLS + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?" +
                    " AND " + MESSAGE_UID + " = ? " +
                    " AND " + ATTACHMENT_NUMBER + " = ?;"
        ).use { statement ->
            statement.setString(1, serialized)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setBytes(3, messageUid.bytes)
            statement.setInt(4, attachmentNumber)
            statement.executeUpdate()
            this.chunkDownloadPrivateUrls = serialized
        }
    }

    @Throws(IOException::class)
    fun deleteAttachmentFile() {
        val attachmentDirectory = File(
            fetchManagerSession.engineBaseDirectory,
            this.attachmentDirectory
        )
        if (!attachmentDirectory.isDirectory()) {
            return
        }
        val attachmentFile = fetchManagerSession.fileIo.file(
            fetchManagerSession.engineBaseDirectory,
            this.url
        )
        if (attachmentFile.exists()) {
            if (!attachmentFile.delete()) {
                throw IOException()
            }
        }
        val fileNames = attachmentDirectory.list()
        if (fileNames != null && fileNames.size == 0) {
            if (!attachmentDirectory.delete()) {
                throw IOException()
            }
        }
    }

    private val attachmentDirectory: String
        get() = Constants.INBOUND_ATTACHMENTS_DIRECTORY + File.separator + ownedIdentity!!.computeUniqueUid()
            .toString() + "-" + messageUid.toString()

    val url: String
        get() = this.attachmentDirectory + File.separator + attachmentNumber

    fun writeToAttachmentFile(attachmentBytes: ByteArray, encryptedLength: Int): Boolean {
        File(fetchManagerSession.engineBaseDirectory, this.attachmentDirectory).mkdirs()
        try {
            fetchManagerSession.fileIo.file(
                fetchManagerSession.engineBaseDirectory!! + File.separator + this.attachmentDirectory,
                attachmentNumber.toString()
            ).openOutput(EngineWriteMode.TRUNCATE, fileSize).use { f ->
                f.write(attachmentBytes)
                fetchManagerSession.session.prepareStatement(
                    "InboxAttachment.writeToAttachmentFile",
                    "UPDATE " + TABLE_NAME + " SET " +
                            RECEIVED_LENGTH + " = ?, " +
                            FILE_SIZE + " = ? " +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + MESSAGE_UID + " = ? " +
                            " AND " + ATTACHMENT_NUMBER + " = ?;"
                ).use { statement ->
                    statement.setLong(1, receivedLength + encryptedLength)
                    statement.setLong(2, fileSize + attachmentBytes.size)
                    statement.setBytes(3, ownedIdentity!!.getBytes())
                    statement.setBytes(4, messageUid.bytes)
                    statement.setInt(5, attachmentNumber)
                    statement.executeUpdate()
                    this.receivedLength += encryptedLength.toLong()
                    this.fileSize += attachmentBytes.size.toLong()
                    if (expectedLength == receivedLength) {
                        commitHookBits = commitHookBits or HOOK_BIT_LAST_CHUNK_RECEIVED
                    }
                    commitHookBits = commitHookBits or HOOK_BIT_CHUNK_RECEIVED
                    fetchManagerSession.session.addSessionCommitListener(this)
                    return true
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    private constructor(
        fetchManagerSession: FetchManagerSession,
        ownedIdentity: Identity,
        messageUid: UID,
        attachmentNumber: Int,
        expectedLength: Long,
        chunkLength: Int,
        uploadCancelled: Boolean,
        chunkDownloadPrivateUrls: Array<String?>?
    ) {
        this.fetchManagerSession = fetchManagerSession
        this.ownedIdentity = ownedIdentity
        this.messageUid = messageUid
        this.attachmentNumber = attachmentNumber
        this.expectedLength = expectedLength
        this.chunkLength = chunkLength
        this.metadata = null
        this.key = null
        this.fileSize = 0
        this.receivedLength = 0
        this.priorityCategory = null
        this.isDownloadRequested = false
        this.timestampOfFetchRequest = null
        this.isMarkedForDeletion = false

        val serialized: String?
        if (uploadCancelled) {
            serialized = UPLOAD_CANCELLED_CHUNK_URLS
        } else if (chunkDownloadPrivateUrls == null || chunkDownloadPrivateUrls.size == 0) {
            serialized = null
        } else {
            val sb = StringBuilder()
            var first = true
            for (chunkDownloadPrivateUrl in chunkDownloadPrivateUrls) {
                if (!first) {
                    sb.append("¦")
                }
                first = false
                sb.append(chunkDownloadPrivateUrl)
            }
            serialized = sb.toString()
        }
        this.chunkDownloadPrivateUrls = serialized
    }

    private constructor(fetchManagerSession: FetchManagerSession, res: ResultSet) {
        this.fetchManagerSession = fetchManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.messageUid = UID(res.getBytes(MESSAGE_UID))
        this.attachmentNumber = res.getInt(ATTACHMENT_NUMBER)
        this.expectedLength = res.getLong(EXPECTED_LENGTH)
        this.chunkLength = res.getInt(CHUNK_LENGTH)
        this.metadata = res.getBytes(METADATA)
        try {
            this.key = Encoded(res.getBytes(KEY)).decodeSymmetricKey() as AuthEncKey?
        } catch (_: Exception) {
            this.key = null
        }
        this.fileSize = res.getLong(FILE_SIZE)
        this.receivedLength = res.getLong(RECEIVED_LENGTH)
        this.priorityCategory = res.getInt(PRIORITY_CATEGORY)
        if (res.wasNull()) {
            this.priorityCategory = null
        }
        this.isDownloadRequested = res.getBoolean(DOWNLOAD_REQUESTED)
        this.timestampOfFetchRequest = res.getLong(TIMESTAMP_OF_FETCH_REQUEST)
        if (res.wasNull()) {
            this.timestampOfFetchRequest = null
        }
        this.isMarkedForDeletion = res.getBoolean(MARKED_FOR_DELETION)
        this.chunkDownloadPrivateUrls = res.getString(CHUNK_DOWNLOAD_PRIVATE_URLS)
    }

    @Throws(SQLException::class)
    override fun insert() {
        fetchManagerSession.session.prepareStatement(
            "InboxAttachment.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES(?,?,?,?,?, ?,?,?,?,?, ?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setInt(3, attachmentNumber)
            statement.setLong(4, expectedLength)
            statement.setInt(5, chunkLength)

            statement.setBytes(6, metadata)
            statement.setBytes(7, if (key == null) null else Encoded.of(key!!).bytes)
            statement.setLong(8, fileSize)
            statement.setLong(9, receivedLength)
            if (priorityCategory == null) {
                statement.setNull(10, Types.INTEGER)
            } else {
                statement.setInt(10, priorityCategory!!)
            }

            statement.setBoolean(11, this.isDownloadRequested)
            if (timestampOfFetchRequest == null) {
                statement.setNull(12, Types.BIGINT)
            } else {
                statement.setLong(12, timestampOfFetchRequest!!)
            }
            statement.setBoolean(13, this.isMarkedForDeletion)
            statement.setString(14, chunkDownloadPrivateUrls)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        fetchManagerSession.session.prepareStatement(
            "InboxAttachment.delete",
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
    // region hooks
    interface InboxAttachmentListener {
        fun attachmentDownloadProgressed(
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int,
            progress: Float
        )

        fun attachmentDownloadFinished(
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int
        )

        fun attachmentDownloadWasRequested(
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int,
            priorityCategory: Int,
            initialPriority: Long
        )
    }

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_CHUNK_RECEIVED) != 0L) {
            if (fetchManagerSession.inboxAttachmentListener != null) {
                fetchManagerSession.inboxAttachmentListener.attachmentDownloadProgressed(
                    ownedIdentity, messageUid, attachmentNumber,
                    this.progress
                )
            }
        }
        if ((commitHookBits and HOOK_BIT_LAST_CHUNK_RECEIVED) != 0L) {
            if (fetchManagerSession.inboxAttachmentListener != null) {
                fetchManagerSession.inboxAttachmentListener.attachmentDownloadFinished(
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                )
            }
        }
        if ((commitHookBits and HOOK_BIT_DOWNLOAD_REQUESTED) != 0L) {
            if (fetchManagerSession.inboxAttachmentListener != null) {
                fetchManagerSession.inboxAttachmentListener.attachmentDownloadWasRequested(
                    ownedIdentity, messageUid, attachmentNumber, priorityCategory!!,
                    this.priority
                )
            }
        }
        commitHookBits = 0
    } // endregion

    companion object {
        const val TABLE_NAME: String = "inbox_attachment"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val MESSAGE_UID: String = "message_uid"
        const val ATTACHMENT_NUMBER: String = "attachment_number"
        const val EXPECTED_LENGTH: String = "expected_length"
        const val CHUNK_LENGTH: String = "chunk_length"
        const val METADATA: String = "metadata"
        const val KEY: String = "key"
        const val FILE_SIZE: String = "file_size"
        const val RECEIVED_LENGTH: String = "received_length"
        const val PRIORITY_CATEGORY: String = "priority_category"
        const val DOWNLOAD_REQUESTED: String = "download_requested"
        const val TIMESTAMP_OF_FETCH_REQUEST: String = "timestamp_of_fetch_request"
        const val MARKED_FOR_DELETION: String = "marked_for_deletion"
        const val CHUNK_DOWNLOAD_PRIVATE_URLS: String = "chunk_download_private_urls"

        const val UPLOAD_CANCELLED_CHUNK_URLS: String = "__CANCELLED__"

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
        @Throws(SQLException::class)
        fun create(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int,
            expectedLength: Long,
            chunkLength: Int,
            chunkDownloadPrivateUrls: Array<String?>?
        ): InboxAttachment? {
            if (ownedIdentity == null || messageUid == null) {
                return null
            }
            val inboxAttachment = InboxAttachment(
                fetchManagerSession,
                ownedIdentity,
                messageUid,
                attachmentNumber,
                expectedLength,
                chunkLength,
                false,
                chunkDownloadPrivateUrls
            )
            inboxAttachment.insert()
            return inboxAttachment
        }

        @Throws(SQLException::class)
        fun createUploadCancelled(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int,
            expectedLength: Long,
            chunkLength: Int
        ) {
            if (ownedIdentity == null || messageUid == null) {
                return
            }
            val inboxAttachment = InboxAttachment(
                fetchManagerSession,
                ownedIdentity,
                messageUid,
                attachmentNumber,
                expectedLength,
                chunkLength,
                true,
                null
            )
            inboxAttachment.insert()
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int
        ): InboxAttachment? {
            if (ownedIdentity == null || messageUid == null) {
                return null
            }
            fetchManagerSession.session.prepareStatement(
                "InboxAttachment.get",
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
                        return InboxAttachment(fetchManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        fun getAll(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?,
            messageUid: UID?
        ): Array<InboxAttachment>? {
            if (ownedIdentity == null || messageUid == null) {
                return null
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxAttachment.getAll",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + MESSAGE_UID + " = ? " +
                            " ORDER BY " + ATTACHMENT_NUMBER + " ASC;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, messageUid.bytes)
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxAttachment> = ArrayList()
                        while (res.next()) {
                            list.add(InboxAttachment(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxAttachment>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getAllDownloaded(fetchManagerSession: FetchManagerSession): Array<InboxAttachment> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxAttachment.getAllDownloaded",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + RECEIVED_LENGTH + " = " + EXPECTED_LENGTH +
                            " AND " + MARKED_FOR_DELETION + " = 0;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxAttachment> = ArrayList()
                        while (res.next()) {
                            list.add(InboxAttachment(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxAttachment>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }


        fun getAllAttachmentsToResume(fetchManagerSession: FetchManagerSession): Array<InboxAttachment> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxAttachment.getAllAttachmentsToResume",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + DOWNLOAD_REQUESTED + " = 1 " +
                            " AND " + KEY + " NOT NULL " +
                            " AND " + RECEIVED_LENGTH + " < " + EXPECTED_LENGTH +
                            " AND " + MARKED_FOR_DELETION + " = 0;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxAttachment> = ArrayList<InboxAttachment>()
                        while (res.next()) {
                            list.add(InboxAttachment(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxAttachment>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getAllPartialAttachmentsNotToResume(fetchManagerSession: FetchManagerSession): Array<InboxAttachment> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "InboxAttachment.getAllPartialAttachmentsNotToResume",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + DOWNLOAD_REQUESTED + " = 0 " +
                            " AND " + KEY + " NOT NULL " +
                            " AND " + RECEIVED_LENGTH + " < " + EXPECTED_LENGTH +
                            " AND " + RECEIVED_LENGTH + " > 0 " +
                            " AND " + MARKED_FOR_DELETION + " = 0;"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<InboxAttachment> = ArrayList()
                        while (res.next()) {
                            list.add(InboxAttachment(fetchManagerSession, res))
                        }
                        return list.toTypedArray<InboxAttachment>()
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
                            MESSAGE_UID + " BLOB NOT NULL, " +
                            ATTACHMENT_NUMBER + " INT, " +
                            EXPECTED_LENGTH + " BIGINT NOT NULL, " +
                            CHUNK_LENGTH + " INT NOT NULL, " +
                            METADATA + " BLOB, " +
                            KEY + " BLOB, " +
                            FILE_SIZE + " BIGINT NOT NULL, " +
                            RECEIVED_LENGTH + " BIGINT NOT NULL, " +
                            PRIORITY_CATEGORY + " INT, " +
                            DOWNLOAD_REQUESTED + " BIT NOT NULL, " +
                            TIMESTAMP_OF_FETCH_REQUEST + " BIGINT, " +
                            MARKED_FOR_DELETION + " BIT NOT NULL, " +
                            CHUNK_DOWNLOAD_PRIVATE_URLS + " TEXT, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + OWNED_IDENTITY + ", " + MESSAGE_UID + ", " + ATTACHMENT_NUMBER + "), " +
                            "FOREIGN KEY (" + OWNED_IDENTITY + ", " + MESSAGE_UID + ") REFERENCES " + InboxMessage.TABLE_NAME + "(" + InboxMessage.OWNED_IDENTITY + ", " + InboxMessage.UID_ + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 4 && newVersion >= 4) {
                Logger.d("MIGRATING `inbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 4\n!!!! THIS MIGRATION IS DESTRUCTIVE !!!!")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE IF EXISTS `inbox_attachment`;")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS inbox_attachment (" +
                                "message_uid BLOB, " +
                                "attachment_number INT, " +
                                "expected_length BIGINT NOT NULL, " +
                                "chunk_length INT NOT NULL, " +
                                "metadata BLOB, " +
                                "key BLOB, " +
                                "file_size BIGINT NOT NULL, " +
                                "received_length BIGINT NOT NULL, " +
                                "priority_category INT, " +
                                "pending_cancel_fetch_request BIT NOT NULL, " +
                                "download_requested BIT NOT NULL, " +
                                "timestamp_of_fetch_request BIGINT, " +
                                "marked_for_deletion BIT NOT NULL, " +
                                "CONSTRAINT PK_inbox_attachment PRIMARY KEY(message_uid, attachment_number), " +
                                "FOREIGN KEY (message_uid) REFERENCES inbox_message(uid));"
                    )
                }
                oldVersion = 4
            }
            if (oldVersion < 8 && newVersion >= 8) {
                Logger.d("MIGRATING `inbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 8")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_attachment RENAME TO old_inbox_attachment")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS inbox_attachment (" +
                                "message_uid BLOB, " +
                                "attachment_number INT, " +
                                "expected_length BIGINT NOT NULL, " +
                                "chunk_length INT NOT NULL, " +
                                "metadata BLOB, " +
                                "key BLOB, " +
                                "file_size BIGINT NOT NULL, " +
                                "received_length BIGINT NOT NULL, " +
                                "priority_category INT, " +
                                "download_requested BIT NOT NULL, " +
                                "timestamp_of_fetch_request BIGINT, " +
                                "marked_for_deletion BIT NOT NULL, " +
                                "CONSTRAINT PK_inbox_attachment PRIMARY KEY(message_uid, attachment_number), " +
                                "FOREIGN KEY (message_uid) REFERENCES inbox_message(uid))"
                    )
                    statement.execute(
                        "INSERT INTO inbox_attachment " +
                                " SELECT message_uid, attachment_number, expected_length, chunk_length, metadata, " +
                                " key, file_size, received_length, priority_category, download_requested, " +
                                " timestamp_of_fetch_request, marked_for_deletion FROM old_inbox_attachment"
                    )
                    statement.execute("DROP TABLE old_inbox_attachment")
                }
                oldVersion = 8
            }
            if (oldVersion < 13 && newVersion >= 13) {
                Logger.d("MIGRATING `inbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 13")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_attachment ADD COLUMN chunk_download_private_urls TEXT DEFAULT NULL;")
                }
                oldVersion = 13
            }
            if (oldVersion < 15 && newVersion >= 15) {
                Logger.d("MIGRATING `inbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 15")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE inbox_attachment RENAME TO old_inbox_attachment")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS inbox_attachment (" +
                                "owned_identity BLOB NOT NULL, " +
                                "message_uid BLOB NOT NULL, " +
                                "attachment_number INT, " +
                                "expected_length BIGINT NOT NULL, " +
                                "chunk_length INT NOT NULL, " +
                                "metadata BLOB, " +
                                "key BLOB, " +
                                "file_size BIGINT NOT NULL, " +
                                "received_length BIGINT NOT NULL, " +
                                "priority_category INT, " +
                                "download_requested BIT NOT NULL, " +
                                "timestamp_of_fetch_request BIGINT, " +
                                "marked_for_deletion BIT NOT NULL, " +
                                "chunk_download_private_urls TEXT, " +
                                "CONSTRAINT PK_inbox_attachment PRIMARY KEY (owned_identity, message_uid, attachment_number), " +
                                "FOREIGN KEY (owned_identity, message_uid) REFERENCES inbox_message(owned_identity, uid))"
                    )
                    statement.execute(
                        "INSERT INTO inbox_attachment " +
                                " SELECT m.owned_identity, a.message_uid, a.attachment_number, a.expected_length, a.chunk_length, a.metadata, " +
                                " a.key, a.file_size, a.received_length, a.priority_category, a.download_requested, " +
                                " a.timestamp_of_fetch_request, a.marked_for_deletion, a.chunk_download_private_urls " +
                                " FROM old_inbox_attachment AS a " +
                                " INNER JOIN inbox_message AS m ON a.message_uid = m.uid"
                    )
                    statement.execute("DROP TABLE old_inbox_attachment")
                }
                oldVersion = 15
            }
            if (oldVersion < 16 && newVersion >= 16) {
                Logger.d("MIGRATING `inbox_attachment` DATABASE FROM VERSION " + oldVersion + " TO 16")
                session.createStatement().use { statement ->
                    statement.execute("UPDATE inbox_attachment SET received_length = 0, file_size = 0")
                }
                oldVersion = 16
            }
        }

        private const val HOOK_BIT_CHUNK_RECEIVED: Long = 0x1
        private const val HOOK_BIT_LAST_CHUNK_RECEIVED: Long = 0x2
        private const val HOOK_BIT_DOWNLOAD_REQUESTED: Long = 0x4
    }
}
