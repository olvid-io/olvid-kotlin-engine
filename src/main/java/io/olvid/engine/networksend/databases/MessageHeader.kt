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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.networksend.datatypes.SendManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class MessageHeader : ObvDatabase {
    private val sendManagerSession: SendManagerSession

    private var ownedIdentity: Identity? = null
    @JvmField val messageUid: UID
    @JvmField val deviceUid: UID
    private var toIdentity: Identity? = null
    @JvmField val wrappedKey: EncryptedBytes
    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun getToIdentity(): Identity {
        return toIdentity!!
    }


    private constructor(
        sendManagerSession: SendManagerSession,
        ownedIdentity: Identity,
        messageUid: UID,
        deviceUid: UID,
        toIdentity: Identity,
        wrappedKey: EncryptedBytes
    ) {
        this.sendManagerSession = sendManagerSession
        this.ownedIdentity = ownedIdentity
        this.messageUid = messageUid
        this.deviceUid = deviceUid
        this.toIdentity = toIdentity
        this.wrappedKey = wrappedKey
    }

    private constructor(sendManagerSession: SendManagerSession, res: ResultSet) {
        this.sendManagerSession = sendManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.messageUid = UID(res.getBytes(MESSAGE_UID))
        this.deviceUid = UID(res.getBytes(DEVICE_UID))
        try {
            this.toIdentity = Identity.of(res.getBytes(TO_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.wrappedKey = EncryptedBytes(res.getBytes(WRAPPED_KEY))
    }


    @Throws(SQLException::class)
    override fun insert() {
        sendManagerSession.session.prepareStatement(
            "MessageHeader.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setBytes(3, deviceUid.bytes)
            statement.setBytes(4, toIdentity!!.getBytes())
            statement.setBytes(5, wrappedKey.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        sendManagerSession.session.prepareStatement(
            "MessageHeader.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + MESSAGE_UID + " = ? " +
                    " AND " + DEVICE_UID + " = ? " +
                    " AND " + TO_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, messageUid.bytes)
            statement.setBytes(3, deviceUid.bytes)
            statement.setBytes(4, toIdentity!!.getBytes())
            statement.executeUpdate()
        }
    }

    override fun wasCommitted() {
        // No hooks
    }

    companion object {
        const val TABLE_NAME: String = "message_header"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val MESSAGE_UID: String = "message_uid"
        const val DEVICE_UID: String = "device_uid"
        const val TO_IDENTITY: String = "to_identity"
        const val WRAPPED_KEY: String = "wrapped_key"

        fun create(
            sendManagerSession: SendManagerSession?,
            ownedIdentity: Identity?,
            messageUid: UID?,
            deviceUid: UID?,
            toIdentity: Identity?,
            wrappedKey: EncryptedBytes?
        ): MessageHeader? {
            if (ownedIdentity == null || messageUid == null || deviceUid == null || toIdentity == null || wrappedKey == null) {
                return null
            }
            try {
                val messageHeader = MessageHeader(
                    sendManagerSession!!,
                    ownedIdentity,
                    messageUid,
                    deviceUid,
                    toIdentity,
                    wrappedKey
                )
                messageHeader.insert()
                return messageHeader
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        fun getAll(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity,
            messageUid: UID?
        ): Array<MessageHeader?>? {
            if (messageUid == null) {
                return null
            }
            try {
                sendManagerSession.session.prepareStatement(
                    "MessageHeader.getAll",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + MESSAGE_UID + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, messageUid.bytes)
                    statement.executeQuery().use { res ->
                        val list: MutableList<MessageHeader?> = ArrayList<MessageHeader?>()
                        while (res.next()) {
                            list.add(MessageHeader(sendManagerSession, res))
                        }
                        return list.toTypedArray<MessageHeader?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<MessageHeader>(0)
            }
        }


        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            MESSAGE_UID + " BLOB NOT NULL, " +
                            DEVICE_UID + " BLOB NOT NULL, " +
                            TO_IDENTITY + " BLOB NOT NULL, " +
                            WRAPPED_KEY + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + MESSAGE_UID + ", " + DEVICE_UID + ", " + TO_IDENTITY + "), " +
                            "FOREIGN KEY (" + OWNED_IDENTITY + ", " + MESSAGE_UID + ") REFERENCES " + OutboxMessage.TABLE_NAME + "(" + OutboxMessage.OWNED_IDENTITY + ", " + OutboxMessage.UID_ + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 3 && newVersion >= 3) {
                Logger.d("MIGRATING `message_header` DATABASE FROM VERSION " + oldVersion + " TO 3\n!!!! THIS MIGRATION IS DESTRUCTIVE !!!!")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE IF EXISTS `message_header`;")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS message_header (" +
                                "message_uid BLOB NOT NULL, " +
                                "device_uid BLOB NOT NULL, " +
                                "to_identity BLOB NOT NULL, " +
                                "wrapped_key BLOB NOT NULL, " +
                                "CONSTRAINT PK_message_header PRIMARY KEY(message_uid, device_uid, to_identity), " +
                                "FOREIGN KEY (message_uid) REFERENCES outbox_message(uid));"
                    )
                }
                oldVersion = 3
            }
            if (oldVersion < 15 && newVersion >= 15) {
                Logger.d("MIGRATING `message_header` DATABASE FROM VERSION " + oldVersion + " TO 15")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE message_header RENAME TO old_message_header")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS message_header (" +
                                "owned_identity BLOB NOT NULL, " +
                                "message_uid BLOB NOT NULL, " +
                                "device_uid BLOB NOT NULL, " +
                                "to_identity BLOB NOT NULL, " +
                                "wrapped_key BLOB NOT NULL, " +
                                "CONSTRAINT PK_message_header PRIMARY KEY(owned_identity, message_uid, device_uid, to_identity), " +
                                "FOREIGN KEY (owned_identity, message_uid) REFERENCES outbox_message(owned_identity, uid));"
                    )
                    statement.execute(
                        "INSERT INTO message_header SELECT i.identity, h.message_uid, h.device_uid, h.to_identity, h.wrapped_key FROM old_message_header AS h" +
                                " CROSS JOIN owned_identity AS i"
                    )
                    statement.execute("DROP TABLE old_message_header")
                }
                oldVersion = 15
            }
        }

        @Throws(SQLException::class)
        fun deleteAll(
            sendManagerSession: SendManagerSession,
            ownedIdentity: Identity,
            messageUid: UID
        ) {
            sendManagerSession.session.prepareStatement(
                "MessageHeader.deleteAll",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + MESSAGE_UID + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, messageUid.bytes)
                statement.executeUpdate()
            }
        }
    }
}
