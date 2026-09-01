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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.datatypes.GenericProtocolMessageToSend
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class WaitingForOneToOneContactProtocolInstance : ObvDatabase {
    internal val protocolManagerSession: ProtocolManagerSession

    @JvmField val protocolUid: UID
    @JvmField val ownedIdentity: Identity
    @JvmField val contactIdentity: Identity
    @JvmField val protocolId: Int
    @JvmField val messageId: Int

    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "WaitingForOneToOneContactProtocolInstance.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, protocolUid.bytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setBytes(3, contactIdentity.getBytes())
            statement.setInt(4, protocolId)
            statement.setInt(5, messageId)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "WaitingForOneToOneContactProtocolInstance.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + PROTOCOL_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + CONTACT_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, protocolUid.bytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setBytes(3, contactIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    internal constructor(
        protocolManagerSession: ProtocolManagerSession,
        protocolUid: UID,
        ownedIdentity: Identity,
        contactIdentity: Identity,
        protocolId: Int,
        messageId: Int
    ) {
        this.protocolManagerSession = protocolManagerSession
        this.protocolUid = protocolUid
        this.ownedIdentity = ownedIdentity
        this.contactIdentity = contactIdentity
        this.protocolId = protocolId
        this.messageId = messageId
    }

    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
        this.protocolManagerSession = protocolManagerSession

        this.protocolUid = UID(res.getBytes(PROTOCOL_UID))
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.protocolId = res.getInt(PROTOCOL_ID)
        this.messageId = res.getInt(MESSAGE_ID)
    }

    val genericProtocolMessageToSendWhenTrustLevelIncreased: GenericProtocolMessageToSend
        get() = GenericProtocolMessageToSend(
            SendChannelInfo.createLocalChannelInfo(ownedIdentity)!!,
            protocolId,
            protocolUid,
            messageId,
            arrayOf(
                Encoded.of(
                    contactIdentity
                )
            ),
            false
        )

    // endregion
    // region hooks
    override fun wasCommitted() {
    } // endregion

    companion object {
        const val TABLE_NAME: String = "waiting_for_one_to_one_contact_protocol_instance"

        const val PROTOCOL_UID: String = "protocol_uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val PROTOCOL_ID: String = "protocol_id"
        const val MESSAGE_ID: String = "message_id"

        // region databases
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            PROTOCOL_UID + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            PROTOCOL_ID + " INTEGER NOT NULL, " +
                            MESSAGE_ID + " INTEGER NOT NULL, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + PROTOCOL_UID + ", " + OWNED_IDENTITY + ", " + CONTACT_IDENTITY + "), " +
                            " FOREIGN KEY (" + PROTOCOL_UID + ", " + OWNED_IDENTITY + ") REFERENCES " + ProtocolInstance.TABLE_NAME + "(" + ProtocolInstance.UID_ + ", " + ProtocolInstance.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `waiting_for_trust_level_increase_protocol_instance` DATABASE FROM VERSION " + oldVersion + " TO 11")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS `waiting_for_trust_level_increase_protocol_instance` (" +
                                "protocol_uid BLOB NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "contact_identity BLOB NOT NULL, " +
                                "protocol_id INTEGER NOT NULL, " +
                                "message_id INTEGER NOT NULL, " +
                                "target_trust_level TEXT NOT NULL, " +
                                " CONSTRAINT PK_waiting_for_trust_level_increase_protocol_instance PRIMARY KEY(protocol_uid, owned_identity, contact_identity), " +
                                " FOREIGN KEY (protocol_uid, owned_identity) REFERENCES protocol_instance(uid, owned_identity) ON DELETE CASCADE);"
                    )
                    statement.execute("DELETE FROM waiting_for_trust_level_increase_protocol_instance WHERE protocol_id = 5;")
                }
                oldVersion = 11
            }
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM waiting_for_trust_level_increase_protocol_instance AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM protocol_instance " +
                                " WHERE uid = p.protocol_uid" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
            if (oldVersion < 28 && newVersion >= 28) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `waiting_for_trust_level_increase_protocol_instance` TABLE FROM VERSION " + oldVersion + " TO 28")
                    statement.execute("ALTER TABLE waiting_for_trust_level_increase_protocol_instance DROP COLUMN target_trust_level")
                    statement.execute("ALTER TABLE waiting_for_trust_level_increase_protocol_instance RENAME TO waiting_for_one_to_one_contact_protocol_instance")
                }
            }
        }

        // endregion
        // region constructor
        fun create(
            protocolManagerSession: ProtocolManagerSession,
            protocolUid: UID?,
            ownedIdentity: Identity?,
            contactIdentity: Identity?,
            protocolId: Int,
            messageId: Int
        ): WaitingForOneToOneContactProtocolInstance? {
            if (protocolUid == null || ownedIdentity == null || contactIdentity == null) {
                return null
            }
            try {
                val instance = WaitingForOneToOneContactProtocolInstance(
                    protocolManagerSession,
                    protocolUid,
                    ownedIdentity,
                    contactIdentity,
                    protocolId,
                    messageId
                )
                instance.insert()
                return instance
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region getters
        fun get(
            protocolManagerSession: ProtocolManagerSession,
            protocolUid: UID?,
            ownedIdentity: Identity?,
            contactIdentity: Identity?
        ): WaitingForOneToOneContactProtocolInstance? {
            if (protocolUid == null || ownedIdentity == null || contactIdentity == null) {
                return null
            }
            try {
                protocolManagerSession.session.prepareStatement(
                    "WaitingForOneToOneContactProtocolInstance.get",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + PROTOCOL_UID + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ? " +
                            " AND " + CONTACT_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, protocolUid.bytes)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.setBytes(3, contactIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        return if (res.next()) {
                            WaitingForOneToOneContactProtocolInstance(
                                protocolManagerSession,
                                res
                            )
                        } else {
                            null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }

        fun getAllForContact(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            contactIdentity: Identity?
        ): Array<WaitingForOneToOneContactProtocolInstance> {
            if (ownedIdentity == null || contactIdentity == null) {
                return emptyArray()
            }
            try {
                protocolManagerSession.session.prepareStatement(
                    "WaitingForOneToOneContactProtocolInstance.getAllForContact",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + CONTACT_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, contactIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<WaitingForOneToOneContactProtocolInstance> =
                            ArrayList()
                        while (res.next()) {
                            list.add(
                                WaitingForOneToOneContactProtocolInstance(
                                    protocolManagerSession,
                                    res
                                )
                            )
                        }
                        return list.toTypedArray<WaitingForOneToOneContactProtocolInstance>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getAll(protocolManagerSession: ProtocolManagerSession): Array<WaitingForOneToOneContactProtocolInstance> {
            try {
                protocolManagerSession.session.prepareStatement(
                    "WaitingForOneToOneContactProtocolInstance.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<WaitingForOneToOneContactProtocolInstance> = ArrayList()
                        while (res.next()) {
                            list.add(
                                WaitingForOneToOneContactProtocolInstance(
                                    protocolManagerSession,
                                    res
                                )
                            )
                        }
                        return list.toTypedArray<WaitingForOneToOneContactProtocolInstance>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "WaitingForOneToOneContactProtocolInstance.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
    }
}
