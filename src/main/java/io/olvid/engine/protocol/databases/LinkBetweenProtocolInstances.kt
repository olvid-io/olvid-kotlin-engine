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
import io.olvid.engine.protocol.datatypes.ChildToParentProtocolMessageInputs
import io.olvid.engine.protocol.datatypes.GenericProtocolMessageToSend
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import java.sql.ResultSet
import java.sql.SQLException


class LinkBetweenProtocolInstances : ObvDatabase {
    internal val protocolManagerSession: ProtocolManagerSession

    @JvmField val childProtocolInstanceUid: UID
    internal val ownedIdentity: Identity
    internal val expectedChildStateId: Int
    @JvmField val parentProtocolInstanceUid: UID
    internal val parentProtocolId: Int
    internal val messageToSendId: Int

    internal constructor(
        protocolManagerSession: ProtocolManagerSession,
        childProtocolInstanceUid: UID,
        ownedIdentity: Identity,
        expectedChildStateId: Int,
        parentProtocolInstanceUid: UID,
        parentProtocolId: Int,
        messageToSendId: Int
    ) {
        this.protocolManagerSession = protocolManagerSession

        this.childProtocolInstanceUid = childProtocolInstanceUid
        this.ownedIdentity = ownedIdentity
        this.expectedChildStateId = expectedChildStateId
        this.parentProtocolInstanceUid = parentProtocolInstanceUid
        this.parentProtocolId = parentProtocolId

        this.messageToSendId = messageToSendId
    }

    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
        this.protocolManagerSession = protocolManagerSession

        this.childProtocolInstanceUid = UID(res.getBytes(CHILD_PROTOCOL_INSTANCE_UID))
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.expectedChildStateId = res.getInt(EXPECTED_CHILD_STATE_ID)
        this.parentProtocolInstanceUid = UID(res.getBytes(PARENT_PROTOCOL_INSTANCE_UID))
        this.parentProtocolId = res.getInt(PARENT_PROTOCOL_ID)
        this.messageToSendId = res.getInt(MESSAGE_TO_SEND_ID)
    }


    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "LinkBetweenProtocolInstances.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, childProtocolInstanceUid.bytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, expectedChildStateId)
            statement.setBytes(4, parentProtocolInstanceUid.bytes)
            statement.setInt(5, parentProtocolId)
            statement.setInt(6, messageToSendId)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "LinkBetweenProtocolInstances.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + CHILD_PROTOCOL_INSTANCE_UID + " = ? AND " + OWNED_IDENTITY + " = ? AND " + EXPECTED_CHILD_STATE_ID + " = ?;"
        ).use { statement ->
            statement.setBytes(1, childProtocolInstanceUid.bytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, expectedChildStateId)
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "link_between_protocol_instances"

        const val CHILD_PROTOCOL_INSTANCE_UID: String = "child_protocol_instance_uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val EXPECTED_CHILD_STATE_ID: String = "expected_child_state_id"
        const val PARENT_PROTOCOL_INSTANCE_UID: String = "parent_protocol_instance_uid"
        const val PARENT_PROTOCOL_ID: String = "parent_protocol_id"
        const val MESSAGE_TO_SEND_ID: String = "message_to_send_id"

        fun create(
            protocolManagerSession: ProtocolManagerSession,
            childProtocolInstanceUid: UID?,
            ownedIdentity: Identity?,
            expectedChildStateId: Int,
            parentProtocolInstanceUid: UID?,
            parentProtocolId: Int,
            messageToSendId: Int
        ): LinkBetweenProtocolInstances? {
            if ((childProtocolInstanceUid == null) || (parentProtocolInstanceUid == null) || (ownedIdentity == null)) {
                return null
            }
            try {
                val linkBetweenProtocolInstances = LinkBetweenProtocolInstances(
                    protocolManagerSession,
                    childProtocolInstanceUid,
                    ownedIdentity,
                    expectedChildStateId,
                    parentProtocolInstanceUid,
                    parentProtocolId,
                    messageToSendId
                )
                linkBetweenProtocolInstances.insert()
                return linkBetweenProtocolInstances
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
                            CHILD_PROTOCOL_INSTANCE_UID + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            EXPECTED_CHILD_STATE_ID + " INT NOT NULL, " +
                            PARENT_PROTOCOL_INSTANCE_UID + " BLOB NOT NULL, " +
                            PARENT_PROTOCOL_ID + " INT NOT NULL, " +
                            MESSAGE_TO_SEND_ID + " INT NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + CHILD_PROTOCOL_INSTANCE_UID + ", " + OWNED_IDENTITY + ", " + EXPECTED_CHILD_STATE_ID + "), " +
                            "FOREIGN KEY (" + PARENT_PROTOCOL_INSTANCE_UID + ", " + OWNED_IDENTITY + ") REFERENCES " + ProtocolInstance.TABLE_NAME + "(" + ProtocolInstance.UID_ + ", " + ProtocolInstance.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    statement.execute("DELETE FROM link_between_protocol_instances WHERE parent_protocol_id = 5;")
                }
                oldVersion = 11
            }
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM link_between_protocol_instances AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM protocol_instance " +
                                " WHERE uid = p.parent_protocol_instance_uid" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
        }

        fun get(
            protocolManagerSession: ProtocolManagerSession,
            childProtocolInstanceUid: UID?,
            ownedIdentity: Identity?,
            expectedChildStateId: Int
        ): LinkBetweenProtocolInstances? {
            if ((childProtocolInstanceUid == null) || (ownedIdentity == null)) {
                return null
            }
            try {
                protocolManagerSession.session.prepareStatement(
                    "LinkBetweenProtocolInstances.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + CHILD_PROTOCOL_INSTANCE_UID + " = ? AND " + OWNED_IDENTITY + " = ? AND " + EXPECTED_CHILD_STATE_ID + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, childProtocolInstanceUid.bytes)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.setInt(3, expectedChildStateId)
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return LinkBetweenProtocolInstances(protocolManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }

        @Throws(SQLException::class)
        fun getAllParentLinks(
            protocolManagerSession: ProtocolManagerSession,
            childProtocolInstanceUid: UID,
            ownedIdentity: Identity
        ): Array<LinkBetweenProtocolInstances?> {
            protocolManagerSession.session.prepareStatement(
                "LinkBetweenProtocolInstances.getAllParentLinks",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + CHILD_PROTOCOL_INSTANCE_UID + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, childProtocolInstanceUid.bytes)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<LinkBetweenProtocolInstances?> =
                        ArrayList<LinkBetweenProtocolInstances?>()
                    while (res.next()) {
                        list.add(LinkBetweenProtocolInstances(protocolManagerSession, res))
                    }
                    return list.toTypedArray<LinkBetweenProtocolInstances?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllChildLinks(
            protocolManagerSession: ProtocolManagerSession,
            parentProtocolInstanceUid: UID,
            ownedIdentity: Identity
        ): Array<LinkBetweenProtocolInstances?> {
            protocolManagerSession.session.prepareStatement(
                "LinkBetweenProtocolInstances.getAllChildLinks",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + PARENT_PROTOCOL_INSTANCE_UID + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, parentProtocolInstanceUid.bytes)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<LinkBetweenProtocolInstances?> =
                        ArrayList<LinkBetweenProtocolInstances?>()
                    while (res.next()) {
                        list.add(LinkBetweenProtocolInstances(protocolManagerSession, res))
                    }
                    return list.toTypedArray<LinkBetweenProtocolInstances?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "LinkBetweenProtocolInstances.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        fun getGenericProtocolMessageToSendWhenChildProtocolInstanceReachesAState(
            protocolManagerSession: ProtocolManagerSession,
            childProtocolInstanceUid: UID?,
            ownedIdentity: Identity?,
            childProtocolState: ConcreteProtocolState
        ): GenericProtocolMessageToSend? {
            val linkBetweenProtocolInstances: LinkBetweenProtocolInstances? = get(
                protocolManagerSession,
                childProtocolInstanceUid,
                ownedIdentity,
                childProtocolState.id
            )
            if (linkBetweenProtocolInstances == null) {
                return null
            }
            Logger.d("Found a LinkBetweenProtocolInstances")
            val inputs = ChildToParentProtocolMessageInputs(
                childProtocolInstanceUid!!,
                childProtocolState
            ).toEncodedInputs()
            val parentProtocolInstance: ProtocolInstance? = ProtocolInstance.get(
                protocolManagerSession,
                linkBetweenProtocolInstances.parentProtocolInstanceUid,
                linkBetweenProtocolInstances.ownedIdentity
            )
            if (parentProtocolInstance == null) {
                return null
            }
            try {
                linkBetweenProtocolInstances.delete()
            } catch (_: SQLException) {
            } // it is not a problem if the delete fails, so no need to handle the exception

            return GenericProtocolMessageToSend(
                SendChannelInfo.createLocalChannelInfo(parentProtocolInstance.ownedIdentity)!!,
                parentProtocolInstance.protocolId,
                parentProtocolInstance.uid,
                linkBetweenProtocolInstances.messageToSendId,
                inputs,
                false
            )
        }
    }
}
