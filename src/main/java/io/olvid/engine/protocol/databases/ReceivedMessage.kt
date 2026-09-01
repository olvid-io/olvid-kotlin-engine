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
package io.olvid.engine.protocol.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.datatypes.GenericReceivedProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types
import java.util.UUID

class ReceivedMessage : ObvDatabase {
    @JvmField val protocolManagerSession: ProtocolManagerSession?

    @JvmField val uid: UID
    @JvmField val toIdentity: Identity
    @JvmField val inputs: Array<Encoded>
    @JvmField val userDialogUuid: UUID?
    @JvmField val encodedResponse: Encoded?
    @JvmField val protocolInstanceUid: UID
    @JvmField val protocolMessageId: Int
    @JvmField val protocolId: Int
    @JvmField val receptionChannelInfo: ReceptionChannelInfo
    internal val expirationTimestamp: Long
    @JvmField val serverTimestamp: Long

    // version (= creation timestamp) of the dialog a dialog-response was answering. 0 means unknown/legacy.
    @JvmField val userDialogVersion: Long

    internal constructor(
        protocolManagerSession: ProtocolManagerSession?,
        toIdentity: Identity,
        inputs: Array<Encoded>,
        userDialogUuid: UUID?,
        encodedResponse: Encoded?,
        protocolInstanceUid: UID,
        protocolMessageId: Int,
        protocolId: Int,
        receptionChannelInfo: ReceptionChannelInfo,
        serverTimestamp: Long,
        userDialogVersion: Long,
        prng: PRNGService
    ) {
        this.protocolManagerSession = protocolManagerSession

        this.uid = UID(prng)
        this.toIdentity = toIdentity
        this.inputs = inputs
        this.userDialogUuid = userDialogUuid
        this.encodedResponse = encodedResponse

        this.protocolInstanceUid = protocolInstanceUid
        this.protocolMessageId = protocolMessageId
        this.protocolId = protocolId
        this.receptionChannelInfo = receptionChannelInfo

        this.expirationTimestamp =
            System.currentTimeMillis() + Constants.PROTOCOL_RECEIVED_MESSAGE_EXPIRATION_DELAY
        this.serverTimestamp = serverTimestamp
        this.userDialogVersion = userDialogVersion
    }


    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
        this.protocolManagerSession = protocolManagerSession


        this.uid = UID(res.getBytes(UID_))
        try {
            this.toIdentity = Identity.of(res.getBytes(TO_IDENTITY))
            this.inputs = Encoded(res.getBytes(INPUTS)).decodeList()
        } catch (_: DecodingException) {
            throw SQLException()
        }
        val uuid: String? = res.getString(USER_DIALOG_UUID)
        if (uuid == null) {
            this.userDialogUuid = null
        } else {
            this.userDialogUuid = UUID.fromString(uuid)
        }
        val udr: ByteArray? = res.getBytes(ENCODED_RESPONSE)
        if (udr == null) {
            this.encodedResponse = null
        } else {
            this.encodedResponse = Encoded(udr)
        }


        this.protocolInstanceUid = UID(res.getBytes(PROTOCOL_INSTANCE_UID))
        this.protocolMessageId = res.getInt(PROTOCOL_MESSAGE_ID)
        this.protocolId = res.getInt(PROTOCOL_ID)
        try {
            this.receptionChannelInfo = ReceptionChannelInfo.of(
                Encoded(
                    res.getBytes(
                        RECEPTION_CHANNEL_INFO
                    )
                )
            )
        } catch (_: DecodingException) {
            throw SQLException()
        }

        this.expirationTimestamp = res.getLong(EXPIRATION_TIMESTAMP)
        this.serverTimestamp = res.getLong(SERVER_TIMESTAMP)
        this.userDialogVersion = res.getLong(USER_DIALOG_VERSION)
    }

    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession!!.session.prepareStatement(
            "ReceivedMessage.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, toIdentity.getBytes())
            statement.setBytes(3, Encoded.of(inputs).bytes)
            if (userDialogUuid != null) {
                statement.setString(4, Logger.getUuidString(userDialogUuid))
            } else {
                statement.setNull(4, Types.VARCHAR)
            }
            if (encodedResponse != null) {
                statement.setBytes(5, encodedResponse.bytes)
            } else {
                statement.setNull(5, Types.BLOB)
            }

            statement.setBytes(6, protocolInstanceUid.bytes)
            statement.setInt(7, protocolMessageId)
            statement.setInt(8, protocolId)
            statement.setBytes(9, receptionChannelInfo.encode().bytes)
            statement.setLong(10, expirationTimestamp)

            statement.setLong(11, serverTimestamp)
            statement.setLong(12, userDialogVersion)
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            protocolManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession!!.session.prepareStatement(
            "ReceivedMessage.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.executeUpdate()
        }
    }


    // endregion
    // region hooks
    internal var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            if (protocolManagerSession?.protocolReceivedMessageProcessorDelegate != null) {
                protocolManagerSession.protocolReceivedMessageProcessorDelegate.processReceivedMessage(
                    uid,
                    protocolId
                )
            }
        }
        commitHookBits = 0
    } // endregion

    companion object {
        const val TABLE_NAME: String = "received_message"
        const val GET_ALL_INDEX_NAME: String = "received_message_get_all_index"

        const val UID_: String = "uid"
        const val TO_IDENTITY: String = "to_identity"
        const val INPUTS: String = "inputs"
        const val USER_DIALOG_UUID: String = "user_dialog_uuid"
        const val ENCODED_RESPONSE: String = "encoded_response"
        const val PROTOCOL_INSTANCE_UID: String = "protocol_instance_uid"
        const val PROTOCOL_MESSAGE_ID: String = "protocol_message_id"
        const val PROTOCOL_ID: String = "protocol_id"
        const val RECEPTION_CHANNEL_INFO: String = "reception_channel_info"
        const val EXPIRATION_TIMESTAMP: String = "expiration_timestamp"
        const val SERVER_TIMESTAMP: String = "server_timestamp"
        const val USER_DIALOG_VERSION: String = "user_dialog_version"

        // region constructors
        fun create(
            protocolManagerSession: ProtocolManagerSession,
            message: GenericReceivedProtocolMessage?,
            prng: PRNGService?
        ): ReceivedMessage? {
            if ((message == null) || (prng == null)) {
                return null
            }
            try {
                val receivedMessage = ReceivedMessage(
                    protocolManagerSession,
                    message.toIdentity!!,
                    message.inputs!!,
                    message.userDialogUuid,
                    message.encodedResponse,
                    message.protocolInstanceUid!!,
                    message.protocolMessageId,
                    message.protocolId,
                    message.receptionChannelInfo!!,
                    message.serverTimestamp,
                    message.userDialogVersion,
                    prng
                )
                receivedMessage.insert()
                return receivedMessage
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
                            UID_ + " BLOB PRIMARY KEY, " +
                            TO_IDENTITY + " BLOB NOT NULL, " +
                            INPUTS + " BLOB NOT NULL, " +
                            USER_DIALOG_UUID + " VARCHAR, " +
                            ENCODED_RESPONSE + " BLOB, " +
                            PROTOCOL_INSTANCE_UID + " BLOB NOT NULL, " +
                            PROTOCOL_MESSAGE_ID + " INT NOT NULL, " +
                            PROTOCOL_ID + " INT NOT NULL, " +
                            RECEPTION_CHANNEL_INFO + " BLOB NOT NULL, " +
                            EXPIRATION_TIMESTAMP + " BIGINT NOT NULL, " +
                            SERVER_TIMESTAMP + " BIGINT NOT NULL, " +
                            USER_DIALOG_VERSION + " BIGINT NOT NULL);"
                )
                statement.execute("CREATE INDEX IF NOT EXISTS " + GET_ALL_INDEX_NAME + " ON " + TABLE_NAME + "(" + TO_IDENTITY + ", " + PROTOCOL_INSTANCE_UID + ")")
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 10 && newVersion >= 10) {
                Logger.d("MIGRATING `received_message` DATABASE FROM VERSION " + oldVersion + " TO 10")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE `received_message` ADD COLUMN `server_timestamp` BIGINT NOT NULL DEFAULT 0")
                }
                oldVersion = 10
            }
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `received_message` DATABASE FROM VERSION " + oldVersion + " TO 11")
                    statement.execute("DELETE FROM received_message WHERE protocol_id = 5;")
                }
                oldVersion = 11
            }
            if (oldVersion < 32 && newVersion >= 32) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `received_message` DATABASE FROM VERSION " + oldVersion + " TO 32")
                    statement.execute("ALTER TABLE `received_message` DROP COLUMN `associated_owned_identity`")
                }
                oldVersion = 32
            }
            if (oldVersion < 46 && newVersion >= 46) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `received_message` DATABASE FROM VERSION " + oldVersion + " TO 46")
                    statement.execute("CREATE INDEX IF NOT EXISTS `received_message_get_all_index` ON `received_message` (`to_identity`, `protocol_instance_uid`)")
                }
                oldVersion = 46
            }
            if (oldVersion < 52 && newVersion >= 52) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `received_message` DATABASE FROM VERSION " + oldVersion + " TO 52")
                    statement.execute("ALTER TABLE `received_message` ADD COLUMN `user_dialog_version` BIGINT NOT NULL DEFAULT 0")
                }
                oldVersion = 52
            }
        }

        @Throws(SQLException::class)
        fun deleteExpiredMessagesWithNoProtocol(protocolManagerSession: ProtocolManagerSession) {
            protocolManagerSession.session.prepareStatement(
                "ReceivedMessage.deleteExpiredMessagesWithNoProtocol",
                "DELETE FROM " + TABLE_NAME + " WHERE " + UID_ + " IN " +
                        " (SELECT " + TABLE_NAME + "." + UID_ + " FROM " + TABLE_NAME +
                        " LEFT JOIN " + ProtocolInstance.TABLE_NAME + " ON " + ProtocolInstance.TABLE_NAME + "." + ProtocolInstance.UID_ + " = " + TABLE_NAME + "." + PROTOCOL_INSTANCE_UID +
                        " WHERE " + TABLE_NAME + "." + EXPIRATION_TIMESTAMP + " < ?" +
                        " AND " + ProtocolInstance.TABLE_NAME + "." + ProtocolInstance.UID_ + " IS NULL);"
            ).use { statement ->
                statement.setLong(1, System.currentTimeMillis())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun deleteAllTransfer(protocolManagerSession: ProtocolManagerSession) {
            protocolManagerSession.session.prepareStatement(
                "ReceivedMessage.deleteAllTransfer",
                "DELETE FROM " + TABLE_NAME + " WHERE " + PROTOCOL_ID + " = ?;"
            ).use { statement ->
                statement.setInt(1, ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID)
                statement.executeUpdate()
            }
        }

        // endregion
        // region getters
        fun get(
            protocolManagerSession: ProtocolManagerSession,
            receivedMessageUid: UID?
        ): ReceivedMessage? {
            if ((receivedMessageUid == null)) {
                return null
            }
            try {
                protocolManagerSession.session.prepareStatement(
                    "ReceivedMessage.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, receivedMessageUid.bytes)
                    statement.executeQuery().use { res ->
                        return if (res.next()) {
                            ReceivedMessage(protocolManagerSession, res)
                        } else {
                            null
                        }
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        @Throws(SQLException::class)
        fun getAll(
            protocolManagerSession: ProtocolManagerSession,
            protocolInstanceUid: UID,
            ownedIdentity: Identity
        ): Array<ReceivedMessage?> {
            protocolManagerSession.session.prepareStatement(
                "ReceivedMessage.getAll",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + TO_IDENTITY + " = ? AND " + PROTOCOL_INSTANCE_UID + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, protocolInstanceUid.bytes)
                statement.executeQuery().use { res ->
                    val list: MutableList<ReceivedMessage?> = ArrayList()
                    while (res.next()) {
                        list.add(ReceivedMessage(protocolManagerSession, res))
                    }
                    return list.toTypedArray<ReceivedMessage?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(protocolManagerSession: ProtocolManagerSession): Array<ReceivedMessage?> {
            protocolManagerSession.session.prepareStatement(
                "ReceivedMessage.getAll2",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ReceivedMessage?> = ArrayList()
                    while (res.next()) {
                        list.add(ReceivedMessage(protocolManagerSession, res))
                    }
                    return list.toTypedArray<ReceivedMessage?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "ReceivedMessage.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + TO_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }


        private const val HOOK_BIT_INSERTED: Long = 0x1
    }
}
