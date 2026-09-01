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
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import java.sql.SQLException

class ChannelCreationPingSignatureReceived(
    internal val protocolManagerSession: ProtocolManagerSession,
    internal val ownedIdentity: Identity,
    internal val signature: ByteArray
) : ObvDatabase {
    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "ChannelCreationPingSignatureReceived.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, signature)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "ChannelCreationPingSignatureReceived.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + SIGNATURE + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, signature)
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "channel_creation_ping_signature_received"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val SIGNATURE: String = "signature"


        fun create(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            signature: ByteArray?
        ): ChannelCreationPingSignatureReceived? {
            if ((ownedIdentity == null) || (signature == null)) {
                return null
            }
            try {
                val channelCreationPingSignatureReceived = ChannelCreationPingSignatureReceived(
                    protocolManagerSession,
                    ownedIdentity,
                    signature
                )
                channelCreationPingSignatureReceived.insert()
                return channelCreationPingSignatureReceived
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
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            SIGNATURE + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + OWNED_IDENTITY + ", " + SIGNATURE + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 30 && newVersion >= 30) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING channel_creation_ping_signature_received DATABASE FROM VERSION " + oldVersion + " TO 30")
                    statement.execute("ALTER TABLE channel_creation_ping_signature_received RENAME TO channel_creation_ping_signature_received_old")
                    statement.execute(
                        "CREATE TABLE channel_creation_ping_signature_received (" +
                                " owned_identity BLOB NOT NULL, " +
                                " signature BLOB NOT NULL, " +
                                " CONSTRAINT PK_channel_creation_ping_signature_received PRIMARY KEY (owned_identity, signature))"
                    )

                    statement.execute("INSERT INTO channel_creation_ping_signature_received SELECT owned_identity, signature FROM channel_creation_ping_signature_received_old")
                    statement.execute("DROP TABLE channel_creation_ping_signature_received_old")
                }
                oldVersion = 30
            }
        }

        @Throws(SQLException::class)
        fun exists(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            signature: ByteArray?
        ): Boolean {
            if ((ownedIdentity == null) || (signature == null)) {
                return false
            }
            protocolManagerSession.session.prepareStatement(
                "ChannelCreationPingSignatureReceived.exists",
                "SELECT 1 FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + SIGNATURE + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, signature)
                statement.executeQuery().use { res ->
                    return res.next()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "ChannelCreationPingSignatureReceived.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
    }
}
