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
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.networksend.datatypes.SendManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class OutboxMessage : ObvDatabase {
    private val sendManagerSession: SendManagerSession

    private var ownedIdentity: Identity? = null
    @JvmField val uid: UID
    var uidFromServer: UID?
        private set
    var nonce: ByteArray?
        private set
    @JvmField val server: String?
    @JvmField val encryptedContent: EncryptedBytes
    @JvmField val isApplicationMessage: Boolean
    @JvmField val isVoipMessage: Boolean
    @JvmField val encryptedExtendedContent: EncryptedBytes?
    @JvmField val creationTimestamp: Long
    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    val headers: Array<MessageHeader?>?
        get() = MessageHeader.getAll(
            sendManagerSession,
            ownedIdentity!!,
            uid
        )

    val attachments: Array<OutboxAttachment?>?
        get() = OutboxAttachment.getAll(sendManagerSession, ownedIdentity, uid)

    val isAcknowledged: Boolean
        get() = uidFromServer != null

    // region setters
    fun setUidFromServer(uidFromServer: UID?, nonce: ByteArray?, timestampFromServer: Long) {
        if (this.uidFromServer !== uidFromServer) {
            try {
                sendManagerSession.session.prepareStatement(
                    "OutboxMessage.setUidFromServer",
                    "UPDATE " + TABLE_NAME +
                            " SET " + UID_FROM_SERVER + " = ?, " +
                            NONCE + " = ? " +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + UID_ + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, if (uidFromServer == null) null else uidFromServer.bytes)
                    statement.setBytes(2, nonce)
                    statement.setBytes(3, ownedIdentity!!.getBytes())
                    statement.setBytes(4, uid.bytes)
                    statement.executeUpdate()
                    this.uidFromServer = uidFromServer
                    this.nonce = nonce
                    this.acknowledgedTimestampFromSever = timestampFromServer
                    if (timestampFromServer != 0L) {
                        this.commitHookBits = this.commitHookBits or HOOK_BIT_ACKNOWLEDGED
                    }
                    sendManagerSession.session.addSessionCommitListener(this)
                }
            } catch (e: SQLException) {
                Logger.x(e)
            }
        }
    }


    private constructor(sendManagerSession: SendManagerSession, res: ResultSet) {
        this.sendManagerSession = sendManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.uid = UID(res.getBytes(UID_))
        var bytes: ByteArray? = res.getBytes(UID_FROM_SERVER)
        this.uidFromServer = if (bytes == null) null else UID(bytes)
        this.nonce = res.getBytes(NONCE)
        this.server = res.getString(SERVER)
        this.encryptedContent = EncryptedBytes(res.getBytes(ENCRYPTED_CONTENT))
        this.isApplicationMessage = res.getBoolean(IS_APPLICATION_MESSAGE)
        this.isVoipMessage = res.getBoolean(IS_VOIP_MESSAGE)
        bytes = res.getBytes(ENCRYPTED_EXTENDED_CONTENT)
        this.encryptedExtendedContent = if (bytes == null) null else EncryptedBytes(bytes)
        this.creationTimestamp = res.getLong(CREATION_TIMESTAMP)
    }

    private constructor(
        sendManagerSession: SendManagerSession,
        ownedIdentity: Identity,
        uid: UID,
        server: String?,
        encryptedContent: EncryptedBytes,
        encryptedExtendedContent: EncryptedBytes?,
        isApplicationMessage: Boolean,
        isVoipMessage: Boolean
    ) {
        this.sendManagerSession = sendManagerSession
        this.ownedIdentity = ownedIdentity
        this.uid = uid
        this.uidFromServer = null
        this.nonce = null
        this.server = server
        this.encryptedContent = encryptedContent
        this.isApplicationMessage = isApplicationMessage
        this.isVoipMessage = isVoipMessage
        this.encryptedExtendedContent = encryptedExtendedContent
        this.creationTimestamp = System.currentTimeMillis()
    }

    @Throws(SQLException::class)
    override fun insert() {
        sendManagerSession.session.prepareStatement(
            "OutboxMessage.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES(?,?,?,?,?, ?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, uid.bytes)
            statement.setBytes(3, if (uidFromServer == null) null else uidFromServer!!.bytes)
            statement.setBytes(4, nonce)
            statement.setString(5, server)

            statement.setBytes(6, encryptedContent.getBytes())
            statement.setBoolean(7, isApplicationMessage)
            statement.setBoolean(8, isVoipMessage)
            statement.setBytes(
                9,
                if (encryptedExtendedContent == null) null else encryptedExtendedContent.getBytes()
            )
            statement.setLong(10, creationTimestamp)

            statement.executeUpdate()
            this.commitHookBits = this.commitHookBits or HOOK_BIT_INSERT
            sendManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        // First, cascade delete MessageHeader and OutboxAttachment
        MessageHeader.deleteAll(sendManagerSession, ownedIdentity!!, uid)
        OutboxAttachment.deleteAll(sendManagerSession, ownedIdentity!!, uid)
        sendManagerSession.session.prepareStatement(
            "OutboxMessage.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, uid.bytes)
            statement.executeUpdate()
        }
    }


    interface NewOutboxMessageListener {
        fun newMessageToSend(
            server: String?,
            ownedIdentity: Identity?,
            messageUid: UID?,
            hasAttachment: Boolean,
            hasUserContent: Boolean
        )
    }

    private var commitHookBits: Long = 0
    private var acknowledgedTimestampFromSever: Long = 0

    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERT) != 0L) {
            if (sendManagerSession.newOutboxMessageListener != null) {
                sendManagerSession.newOutboxMessageListener.newMessageToSend(
                    server,
                    ownedIdentity,
                    uid,
                    (commitHookBits and HOOK_BIT_HAS_ATTACHMENTS) != 0L,
                    isApplicationMessage
                )
            }
        }
        if ((commitHookBits and HOOK_BIT_ACKNOWLEDGED) != 0L) {
            for (outboxAttachment in this.attachments!!) {
                outboxAttachment?.messageIsAcknowledged()
            }
            val userInfo = HashMap<String, Any>()
            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED_OWNED_IDENTITY_KEY] = ownedIdentity!!
            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED_UID_KEY] = uid
            userInfo[UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED_TIMESTAMP_FROM_SERVER] = acknowledgedTimestampFromSever
            if (sendManagerSession.notificationPostingDelegate != null) {
                sendManagerSession.notificationPostingDelegate.postNotification(
                    UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED,
                    userInfo
                )
            }
        }
        commitHookBits = 0
    }

    companion object {
        const val TABLE_NAME: String = "outbox_message"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val UID_: String = "uid"
        const val UID_FROM_SERVER: String = "uid_from_server"
        const val NONCE: String = "nonce"
        const val SERVER: String = "server"
        const val ENCRYPTED_CONTENT: String = "encrypted_content"
        const val IS_APPLICATION_MESSAGE: String = "is_application_message"
        const val IS_VOIP_MESSAGE: String = "is_voip_message"
        const val ENCRYPTED_EXTENDED_CONTENT: String = "encrypted_extended_content"
        const val CREATION_TIMESTAMP: String = "creation_timestamp"


        // endregion
        // region constructors
        fun create(
            sendManagerSession: SendManagerSession?,
            ownedIdentity: Identity?,
            uid: UID?,
            server: String?,
            encryptedContent: EncryptedBytes?,
            encryptedExtendedContent: EncryptedBytes?,
            isApplicationMessage: Boolean,
            isVoipMessage: Boolean,
            hasAttachments: Boolean
        ): OutboxMessage? {
            if (ownedIdentity == null || uid == null || server == null || encryptedContent == null) {
                return null
            }
            try {
                val outboxMessage = OutboxMessage(
                    sendManagerSession!!,
                    ownedIdentity,
                    uid,
                    server,
                    encryptedContent,
                    encryptedExtendedContent,
                    isApplicationMessage,
                    isVoipMessage
                )
                outboxMessage.insert()
                if (hasAttachments) {
                    outboxMessage.commitHookBits =
                        outboxMessage.commitHookBits or HOOK_BIT_HAS_ATTACHMENTS
                }
                return outboxMessage
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region getter
        @Throws(SQLException::class)
        fun get(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity?,
            uid: UID?
        ): OutboxMessage? {
            if (ownedIdentity == null || uid == null) {
                return null
            }
            sendManagerSession.session.prepareStatement(
                "OutboxMessage.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + UID_ + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, uid.bytes)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OutboxMessage(sendManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getManyWithoutUidFromServer(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity,
            server: String?,
            uids: Array<UID?>?
        ): Array<OutboxMessage?>? {
            if (uids == null) {
                return null
            }

            // build a ?,? string
            var count = uids.size
            val sb = StringBuilder(count * 2)
            while (count-- > 1) {
                sb.append("?,")
            }
            sb.append("?")

            sendManagerSession.session.prepareStatement(
                "OutboxMessage.getManyWithoutUidFromServer",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + SERVER + " = ? " +
                        " AND " + UID_FROM_SERVER + " IS NULL " +
                        " AND " + UID_ + " IN (" + sb + ");"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setString(2, server)
                for (i in uids.indices) {
                    statement.setBytes(i + 3, uids[i]!!.bytes)
                }
                statement.executeQuery().use { res ->
                    val list: MutableList<OutboxMessage?> = ArrayList<OutboxMessage?>()
                    while (res.next()) {
                        list.add(OutboxMessage(sendManagerSession, res))
                    }
                    return list.toTypedArray<OutboxMessage?>()
                }
            }
        }

        fun getAll(sendManagerSession: SendManagerSession): Array<OutboxMessage?> {
            try {
                sendManagerSession.session.prepareStatement(
                    "OutboxMessage.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<OutboxMessage?> = ArrayList<OutboxMessage?>()
                        while (res.next()) {
                            list.add(OutboxMessage(sendManagerSession, res))
                        }
                        return list.toTypedArray<OutboxMessage?>()
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return arrayOfNulls<OutboxMessage>(0)
            }
        }

        @Throws(SQLException::class)
        fun getAllForOwnedIdentity(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity
        ): Array<OutboxMessage?> {
            sendManagerSession.session.prepareStatement(
                "OutboxMessage.getAllForOwnedIdentity",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<OutboxMessage?> = ArrayList<OutboxMessage?>()
                    while (res.next()) {
                        list.add(OutboxMessage(sendManagerSession, res))
                    }
                    return list.toTypedArray<OutboxMessage?>()
                }
            }
        }

        // endregion
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            UID_ + " BLOB NOT NULL, " +
                            UID_FROM_SERVER + " BLOB, " +
                            NONCE + " BLOB, " +
                            SERVER + " TEXT NOT NULL, " +
                            ENCRYPTED_CONTENT + " BLOB NOT NULL, " +
                            IS_APPLICATION_MESSAGE + " BIT NOT NULL, " +
                            IS_VOIP_MESSAGE + " BIT NOT NULL, " +
                            ENCRYPTED_EXTENDED_CONTENT + " BLOB, " +
                            CREATION_TIMESTAMP + " BIGINT NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + UID_ + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 3 && newVersion >= 3) {
                Logger.d("MIGRATING `outbox_message` DATABASE FROM VERSION " + oldVersion + " TO 3\n!!!! THIS MIGRATION IS DESTRUCTIVE !!!!")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE IF EXISTS `outbox_message`;")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS outbox_message (" +
                                "uid BLOB PRIMARY KEY, " +
                                "uid_from_server BLOB, " +
                                "server TEXT NOT NULL, " +
                                "encrypted_content BLOB NOT NULL, " +
                                "proof_of_work_uid BLOB, " +
                                "proof_of_work_encoded_challenge BLOB, " +
                                "proof_of_work_encoded_solution BLOB);"
                    )
                }
                oldVersion = 3
            }
            if (oldVersion < 7 && newVersion >= 7) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_message ADD COLUMN is_application_message BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 7
            }
            if (oldVersion < 15 && newVersion >= 15) {
                Logger.d("MIGRATING `outbox_message` DATABASE FROM VERSION " + oldVersion + " TO 15")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_message RENAME TO old_outbox_message")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS outbox_message (" +
                                "owned_identity BLOB NOT NULL, " +
                                "uid BLOB NOT NULL, " +
                                "uid_from_server BLOB, " +
                                "nonce BLOB, " +
                                "server TEXT NOT NULL, " +
                                "encrypted_content BLOB NOT NULL, " +
                                "proof_of_work_uid BLOB, " +
                                "proof_of_work_encoded_challenge BLOB, " +
                                "proof_of_work_encoded_solution BLOB," +
                                "is_application_message BIT NOT NULL," +
                                "CONSTRAINT PK_outbox_message PRIMARY KEY(owned_identity, uid));"
                    )
                    statement.execute(
                        "INSERT INTO outbox_message SELECT i.identity, m.uid, m.uid_from_server, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', m.server, m.encrypted_content, m.proof_of_work_uid, m.proof_of_work_encoded_challenge, m.proof_of_work_encoded_solution, m.is_application_message FROM old_outbox_message AS m" +
                                " CROSS JOIN owned_identity AS i"
                    )
                    statement.execute("DROP TABLE old_outbox_message")
                }
                oldVersion = 15
            }
            if (oldVersion < 17 && newVersion >= 17) {
                Logger.d("MIGRATING `outbox_message` DATABASE FROM VERSION " + oldVersion + " TO 17")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_message RENAME TO old_outbox_message")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS outbox_message (" +
                                "owned_identity BLOB NOT NULL, " +
                                "uid BLOB NOT NULL, " +
                                "uid_from_server BLOB, " +
                                "nonce BLOB, " +
                                "server TEXT NOT NULL, " +
                                "encrypted_content BLOB NOT NULL, " +
                                "proof_of_work_uid BLOB, " +
                                "proof_of_work_encoded_challenge BLOB, " +
                                "proof_of_work_encoded_solution BLOB," +
                                "is_application_message BIT NOT NULL," +
                                "is_voip_message BIT NOT NULL," +
                                "CONSTRAINT PK_outbox_message PRIMARY KEY(owned_identity, uid));"
                    )
                    statement.execute("INSERT INTO outbox_message SELECT owned_identity, uid, uid_from_server, nonce, server, encrypted_content, proof_of_work_uid, proof_of_work_encoded_challenge, proof_of_work_encoded_solution, is_application_message, 0  FROM old_outbox_message")
                    statement.execute("DROP TABLE old_outbox_message")
                }
                oldVersion = 17
            }
            if (oldVersion < 22 && newVersion >= 22) {
                Logger.d("MIGRATING `outbox_message` DATABASE FROM VERSION " + oldVersion + " TO 22")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_message ADD COLUMN `encrypted_extended_content` BLOB DEFAULT NULL")
                }
                oldVersion = 22
            }
            if (oldVersion < 29 && newVersion >= 29) {
                Logger.d("MIGRATING `outbox_message` DATABASE FROM VERSION " + oldVersion + " TO 29")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE outbox_message RENAME TO old_outbox_message")
                    statement.execute(
                        "CREATE TABLE outbox_message (" +
                                "owned_identity BLOB NOT NULL, " +
                                "uid BLOB NOT NULL, " +
                                "uid_from_server BLOB, " +
                                "nonce BLOB, " +
                                "server TEXT NOT NULL, " +
                                "encrypted_content BLOB NOT NULL, " +
                                "is_application_message BIT NOT NULL," +
                                "is_voip_message BIT NOT NULL," +
                                "encrypted_extended_content BLOB," +
                                "creation_timestamp BIGINT NOT NULL," +
                                "CONSTRAINT PK_outbox_message PRIMARY KEY(owned_identity, uid));"
                    )

                    session.prepareStatement(
                        "INSERT INTO outbox_message " +
                                "SELECT m.owned_identity, m.uid," +
                                " m.uid_from_server, m.nonce," +
                                " m.server, m.encrypted_content," +
                                " m.is_application_message, m.is_voip_message," +
                                " m.encrypted_extended_content, ? " +
                                " FROM old_outbox_message AS m"
                    ).use { preparedStatement ->
                        preparedStatement.setLong(1, System.currentTimeMillis())
                        preparedStatement.executeUpdate()
                    }
                    statement.execute("DROP TABLE old_outbox_message")
                }
                oldVersion = 29
            }
        }

        private const val HOOK_BIT_INSERT: Long = 0x1
        private const val HOOK_BIT_ACKNOWLEDGED: Long = 0x2
        private const val HOOK_BIT_HAS_ATTACHMENTS: Long = 0x4
    }
}
