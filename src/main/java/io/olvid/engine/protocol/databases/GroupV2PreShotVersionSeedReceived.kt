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
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class GroupV2PreShotVersionSeedReceived : ObvDatabase {
    private val protocolManagerSession: ProtocolManagerSession

    private val ownedIdentity: Identity
    private val groupIdentifier: ByteArray
    private val preShotVersionSeed: ByteArray
    private val creationTimestamp: Long

    val versionSeed: Seed
        get() = Seed(preShotVersionSeed)


    // region constructors

    private constructor(
        protocolManagerSession: ProtocolManagerSession,
        ownedIdentity: Identity,
        groupIdentifier: ByteArray,
        preShotVersionSeed: ByteArray,
        creationTimestamp: Long
    ) {
        this.protocolManagerSession = protocolManagerSession
        this.ownedIdentity = ownedIdentity
        this.groupIdentifier = groupIdentifier
        this.preShotVersionSeed = preShotVersionSeed
        this.creationTimestamp = creationTimestamp
    }

    internal constructor(protocolManagerSession: ProtocolManagerSession, res: ResultSet) {
        this.protocolManagerSession = protocolManagerSession

        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.groupIdentifier = res.getBytes(GROUP_IDENTIFIER)
        this.preShotVersionSeed = res.getBytes(PRE_SHOT_VERSION_SEED)
        this.creationTimestamp = res.getLong(CREATION_TIMESTAMP)
    }

    // endregion


    // region database

    @Throws(SQLException::class)
    override fun insert() {
        protocolManagerSession.session.prepareStatement(
            "GroupV2PreShotVersionSeedReceived.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, groupIdentifier)
            statement.setBytes(3, preShotVersionSeed)
            statement.setLong(4, creationTimestamp)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        protocolManagerSession.session.prepareStatement(
            "GroupV2PreShotVersionSeedReceived.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + GROUP_IDENTIFIER + " = ? AND " + PRE_SHOT_VERSION_SEED + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, groupIdentifier)
            statement.setBytes(3, preShotVersionSeed)
            statement.executeUpdate()
        }
    }

    // endregion

    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "group_v2_pre_shot_version_seed_received"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val GROUP_IDENTIFIER: String = "group_identifier"
        const val PRE_SHOT_VERSION_SEED: String = "pre_shot_version_seed"
        const val CREATION_TIMESTAMP: String = "creation_timestamp"


        // region constructors
        @JvmStatic
        fun create(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            preShotVersionSeed: Seed?
        ): GroupV2PreShotVersionSeedReceived? {
            if (ownedIdentity == null || groupIdentifier == null || preShotVersionSeed == null) {
                return null
            }
            try {
                val groupV2PreShotVersionSeedReceived = GroupV2PreShotVersionSeedReceived(
                    protocolManagerSession,
                    ownedIdentity,
                    groupIdentifier.bytes,
                    preShotVersionSeed.bytes,
                    System.currentTimeMillis()
                )
                groupV2PreShotVersionSeedReceived.insert()
                return groupV2PreShotVersionSeedReceived
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region database
        @JvmStatic
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            GROUP_IDENTIFIER + " BLOB NOT NULL, " +
                            PRE_SHOT_VERSION_SEED + " BLOB NOT NULL, " +
                            CREATION_TIMESTAMP + " INTEGER NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY (" + OWNED_IDENTITY + ", " + GROUP_IDENTIFIER + ", " + PRE_SHOT_VERSION_SEED + "));"
                )
            }
        }

        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            @Suppress("NAME_SHADOWING") var oldVersion = oldVersion
            if (oldVersion < 50 && newVersion >= 50) {
                Logger.d("CREATING `group_v2_pre_shot_version_seed_received` TABLE AS PART OF VERSION 50")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS group_v2_pre_shot_version_seed_received (" +
                                " owned_identity BLOB NOT NULL, " +
                                " group_identifier BLOB NOT NULL, " +
                                " pre_shot_version_seed BLOB NOT NULL, " +
                                " creation_timestamp INTEGER NOT NULL, " +
                                "CONSTRAINT PK_group_v2_pre_shot_version_seed_received PRIMARY KEY (owned_identity, group_identifier, pre_shot_version_seed));"
                    )
                }
                oldVersion = 50
            }
        }

        // endregion

        @JvmStatic
        @Throws(SQLException::class)
        fun getAllForGroupIdentifier(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): List<GroupV2PreShotVersionSeedReceived> {
            if (ownedIdentity == null || groupIdentifier == null) {
                return emptyList()
            }
            protocolManagerSession.session.prepareStatement(
                "GroupV2PreShotVersionSeedReceived.getAllForGroupIdentifier",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + GROUP_IDENTIFIER + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, groupIdentifier.bytes)
                statement.executeQuery().use { res ->
                    val list = mutableListOf<GroupV2PreShotVersionSeedReceived>()
                    while (res.next()) {
                        list.add(GroupV2PreShotVersionSeedReceived(protocolManagerSession, res))
                    }
                    return list
                }
            }
        }

        @JvmStatic
        @Throws(SQLException::class)
        fun expire(protocolManagerSession: ProtocolManagerSession, timestamp: Long) {
            protocolManagerSession.session.prepareStatement(
                "GroupV2PreShotVersionSeedReceived.expire",
                "DELETE FROM " + TABLE_NAME + " WHERE " + CREATION_TIMESTAMP + " < ?;"
            ).use { statement ->
                statement.setLong(1, timestamp)
                statement.executeUpdate()
            }
        }

        @JvmStatic
        @Throws(SQLException::class)
        fun deleteAllForGroupIdentifier(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier
        ) {
            protocolManagerSession.session.prepareStatement(
                "GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + GROUP_IDENTIFIER + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, groupIdentifier.bytes)
                statement.executeUpdate()
            }
        }

        @JvmStatic
        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(
            protocolManagerSession: ProtocolManagerSession,
            ownedIdentity: Identity
        ) {
            protocolManagerSession.session.prepareStatement(
                "GroupV2PreShotVersionSeedReceived.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
    }
}
