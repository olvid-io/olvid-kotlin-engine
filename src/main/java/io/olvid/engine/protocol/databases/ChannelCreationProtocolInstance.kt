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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import java.sql.ResultSet
import java.sql.SQLException

class ChannelCreationProtocolInstance : ObvDatabase {
    internal val protocolManagerSession: ProtocolManagerSession

    internal val contactDeviceUid: UID
    internal val contactIdentity: Identity
    internal val ownedIdentity: Identity
    @JvmField val protocolInstanceUid: UID


    internal constructor(
        protocolManagerSession: ProtocolManagerSession,
        contactDeviceUid: UID,
        contactIdentity: Identity,
        ownedIdentity: Identity,
        protocolInstanceUid: UID
    ) {
        this.protocolManagerSession = protocolManagerSession

        this.contactDeviceUid = contactDeviceUid
        this.contactIdentity = contactIdentity
        this.ownedIdentity = ownedIdentity
        this.protocolInstanceUid = protocolInstanceUid
    }

    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
        this.protocolManagerSession = protocolManagerSession

        this.contactDeviceUid = UID(res.getBytes(CONTACT_DEVICE_UID))
        try {
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.protocolInstanceUid = UID(res.getBytes(PROTOCOL_INSTANCE_UID))
    }


    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "ChannelCreationProtocolInstance.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, contactDeviceUid.bytes)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.setBytes(4, protocolInstanceUid.bytes)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "ChannelCreationProtocolInstance.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + CONTACT_DEVICE_UID + " = ? AND " + CONTACT_IDENTITY + " = ? AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, contactDeviceUid.bytes)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "channel_creation_protocol_instance"

        const val CONTACT_DEVICE_UID: String = "contact_device_uid"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val PROTOCOL_INSTANCE_UID: String = "protocol_instance_uid"

        fun create(
            protocolManagerSession: ProtocolManagerSession,
            contactDeviceUid: UID?,
            contactIdentity: Identity?,
            ownedIdentity: Identity?,
            protocolInstanceUid: UID?
        ): ChannelCreationProtocolInstance? {
            if ((contactDeviceUid == null) || (contactIdentity == null) || (ownedIdentity == null) || (protocolInstanceUid == null)) {
                return null
            }
            val protocolInstance: ProtocolInstance? = ProtocolInstance.get(
                protocolManagerSession,
                protocolInstanceUid,
                ownedIdentity
            )
            if ((protocolInstance == null)
                || (protocolInstance.protocolId != ConcreteProtocol.CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID && protocolInstance.protocolId != ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID)
            ) {
                return null
            }
            try {
                val channelCreationProtocolInstance = ChannelCreationProtocolInstance(
                    protocolManagerSession,
                    contactDeviceUid,
                    contactIdentity,
                    ownedIdentity,
                    protocolInstanceUid
                )
                channelCreationProtocolInstance.insert()
                return channelCreationProtocolInstance
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            CONTACT_DEVICE_UID + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            PROTOCOL_INSTANCE_UID + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + CONTACT_DEVICE_UID + ", " + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + "), " +
                            "FOREIGN KEY (" + PROTOCOL_INSTANCE_UID + ", " + OWNED_IDENTITY + ") REFERENCES " + ProtocolInstance.TABLE_NAME + "(" + ProtocolInstance.UID_ + ", " + ProtocolInstance.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM channel_creation_protocol_instance AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM protocol_instance " +
                                " WHERE uid = p.protocol_instance_uid" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
        }

        @Throws(SQLException::class)
        fun get(
            protocolManagerSession: ProtocolManagerSession,
            contactDeviceUid: UID?,
            contactIdentity: Identity?,
            ownedIdentity: Identity?
        ): ChannelCreationProtocolInstance? {
            if ((contactDeviceUid == null) || (ownedIdentity == null) || (contactIdentity == null)) {
                return null
            }
            protocolManagerSession.session.prepareStatement(
                "ChannelCreationProtocolInstance.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + CONTACT_DEVICE_UID + " = ? AND " + CONTACT_IDENTITY + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactDeviceUid.bytes)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return ChannelCreationProtocolInstance(protocolManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllForContact(
            protocolManagerSession: ProtocolManagerSession,
            contactIdentity: Identity?,
            ownedIdentity: Identity?
        ): Array<ChannelCreationProtocolInstance?>? {
            if ((ownedIdentity == null) || (contactIdentity == null)) {
                return null
            }
            protocolManagerSession.session.prepareStatement(
                "ChannelCreationProtocolInstance.getAllForContact",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + CONTACT_IDENTITY + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactIdentity.getBytes())
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ChannelCreationProtocolInstance?> =
                        ArrayList<ChannelCreationProtocolInstance?>()
                    while (res.next()) {
                        list.add(ChannelCreationProtocolInstance(protocolManagerSession, res))
                    }
                    return list.toTypedArray<ChannelCreationProtocolInstance?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "ChannelCreationProtocolInstance.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
    }
}
