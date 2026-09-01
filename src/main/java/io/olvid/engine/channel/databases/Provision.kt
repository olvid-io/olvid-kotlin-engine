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
package io.olvid.engine.channel.databases

import io.olvid.engine.Logger
import io.olvid.engine.channel.datatypes.ChannelManagerSession
import io.olvid.engine.channel.datatypes.RatchetingOutput
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import java.sql.ResultSet
import java.sql.SQLException


class Provision : ObvDatabase {
    private val channelManagerSession: ChannelManagerSession

    @JvmField val fullRatchetingCount: Int
    private var selfRatchetingCount: Int
    private var seedForNextProvisionedReceiveKey: Seed
    private val obliviousEngineVersion: Int
    // foreign key for an ObliviousChannel
    @JvmField val obliviousChannelCurrentDeviceUid: UID
    @JvmField val obliviousChannelRemoteDeviceUid: UID
    @JvmField val obliviousChannelRemoteIdentity: Identity


    private fun selfRatchet(count: Int) {
        // First generate all the new Key Material
        for (i in 0..<count) {
            val ratchetingOutput: RatchetingOutput? = ObliviousChannel.computeSelfRatchet(
                seedForNextProvisionedReceiveKey,
                obliviousEngineVersion
            )
            if (ratchetingOutput == null) {
                Logger.e("ObliviousChannel.computeSelfRatchet() returned null, this should never happen!")
                continue
            }
            seedForNextProvisionedReceiveKey = ratchetingOutput.ratchetedSeed!!
            ProvisionedKeyMaterial.create(
                channelManagerSession,
                ratchetingOutput.keyId,
                ratchetingOutput.authEncKey,
                selfRatchetingCount,
                this
            )
            selfRatchetingCount++
        }
        // Then update the current Provision
        try {
            channelManagerSession.session.prepareStatement(
                "Provision.selfRatchet",
                "UPDATE " + TABLE_NAME + " SET " +
                        SEED_FOR_NEXT_PROVISIONED_RECEIVE_KEY + " = ?, " +
                        SELF_RATCHETING_COUNT + " = ? " +
                        " WHERE " + FULL_RATCHETING_COUNT + " = ? AND " +
                        OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ? AND " +
                        OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = ? AND " +
                        OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, seedForNextProvisionedReceiveKey.getBytes())
                statement.setInt(2, selfRatchetingCount)
                statement.setInt(3, fullRatchetingCount)
                statement.setBytes(4, obliviousChannelCurrentDeviceUid.bytes)
                statement.setBytes(5, obliviousChannelRemoteDeviceUid.bytes)
                statement.setBytes(6, obliviousChannelRemoteIdentity.getBytes())
                statement.executeUpdate()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    fun selfRatchetIfRequired() {
        val remainingKeyMaterialCount: Int =
            ProvisionedKeyMaterial.countNotExpiringProvisionedReceiveKey(
                channelManagerSession,
                this
            )
        if (remainingKeyMaterialCount < Constants.REPROVISIONING_THRESHOLD) {
            selfRatchet(Constants.REPROVISIONING_THRESHOLD)
        }
    }

    private constructor(
        channelManagerSession: ChannelManagerSession,
        fullRatchetingCount: Int,
        obliviousChannel: ObliviousChannel,
        seedForNextProvisionedReceiveKey: Seed,
        obliviousEngineVersion: Int
    ) {
        this.channelManagerSession = channelManagerSession
        this.fullRatchetingCount = fullRatchetingCount
        this.selfRatchetingCount = 0
        this.seedForNextProvisionedReceiveKey = seedForNextProvisionedReceiveKey
        this.obliviousEngineVersion = obliviousEngineVersion
        this.obliviousChannelCurrentDeviceUid = obliviousChannel.currentDeviceUid
        this.obliviousChannelRemoteDeviceUid = obliviousChannel.remoteDeviceUid
        this.obliviousChannelRemoteIdentity = obliviousChannel.remoteIdentity
    }

    private constructor(channelManagerSession: ChannelManagerSession, res: ResultSet) {
        this.channelManagerSession = channelManagerSession
        this.fullRatchetingCount = res.getInt(FULL_RATCHETING_COUNT)
        this.selfRatchetingCount = res.getInt(SELF_RATCHETING_COUNT)
        this.seedForNextProvisionedReceiveKey = Seed(
            res.getBytes(
                SEED_FOR_NEXT_PROVISIONED_RECEIVE_KEY
            )
        )
        this.obliviousEngineVersion = res.getInt(OBLIVIOUS_ENGINE_VERSION)
        this.obliviousChannelCurrentDeviceUid = UID(
            res.getBytes(
                OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID
            )
        )
        this.obliviousChannelRemoteDeviceUid =
            UID(res.getBytes(OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID))
        try {
            this.obliviousChannelRemoteIdentity = Identity.of(
                res.getBytes(
                    OBLIVIOUS_CHANNEL_REMOTE_IDENTITY
                )
            )
        } catch (_: DecodingException) {
            throw SQLException()
        }
    }


    @Throws(SQLException::class)
    override fun insert() {
        channelManagerSession.session.prepareStatement(
            "Provision.insert",
            "INSERT OR REPLACE INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setInt(1, fullRatchetingCount)
            statement.setInt(2, selfRatchetingCount)
            statement.setBytes(3, seedForNextProvisionedReceiveKey.getBytes())
            statement.setInt(4, obliviousEngineVersion)
            statement.setBytes(5, obliviousChannelCurrentDeviceUid.bytes)
            statement.setBytes(6, obliviousChannelRemoteDeviceUid.bytes)
            statement.setBytes(7, obliviousChannelRemoteIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        channelManagerSession.session.prepareStatement(
            "Provision.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + FULL_RATCHETING_COUNT + " = ? AND " + OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ? AND " + OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = ? AND " + OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, fullRatchetingCount)
            statement.setBytes(2, obliviousChannelCurrentDeviceUid.bytes)
            statement.setBytes(3, obliviousChannelRemoteDeviceUid.bytes)
            statement.setBytes(4, obliviousChannelRemoteIdentity.getBytes())
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // No hooks here
    }

    companion object {
        const val TABLE_NAME: String = "provision"

        const val FULL_RATCHETING_COUNT: String = "full_ratcheting_count"
        const val SELF_RATCHETING_COUNT: String = "self_ratcheting_count"
        const val SEED_FOR_NEXT_PROVISIONED_RECEIVE_KEY: String =
            "seed_for_next_provisioned_receive_key"
        const val OBLIVIOUS_ENGINE_VERSION: String = "oblivious_engine_version"

        const val OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID: String =
            "oblivious_channel_current_device_uid"
        const val OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID: String =
            "oblivious_channel_remote_device_uid"
        const val OBLIVIOUS_CHANNEL_REMOTE_IDENTITY: String = "oblivious_channel_remote_identity"

        fun deleteAllEmpty(channelManagerSession: ChannelManagerSession) {
            // delete all Provision, with no ProvisionedKeyMaterial.
            try {
                channelManagerSession.session.prepareStatement(
                    "Provision.deleteAllEmpty",
                    "DELETE FROM " + TABLE_NAME + " AS p " +
                            " WHERE NOT EXISTS (" +
                            " SELECT 1 FROM " + ProvisionedKeyMaterial.TABLE_NAME +
                            " WHERE " + ProvisionedKeyMaterial.PROVISION_FULL_RATCHETING_COUNT + " = p." + FULL_RATCHETING_COUNT +
                            " AND " + ProvisionedKeyMaterial.PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = p." + OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID +
                            " AND " + ProvisionedKeyMaterial.PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = p." + OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID +
                            " AND " + ProvisionedKeyMaterial.PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = p." + OBLIVIOUS_CHANNEL_REMOTE_IDENTITY +
                            ")"
                ).use { statement ->
                    statement.executeUpdate()
                }
            } catch (e: SQLException) {
                Logger.x(e)
            }
        }


        fun createOrReplace(
            channelManagerSession: ChannelManagerSession,
            fullRatchetingCount: Int,
            obliviousChannel: ObliviousChannel?,
            seedForNextProvisionedReceiveKey: Seed?,
            obliviousEngineVersion: Int
        ): Provision? {
            if ((obliviousChannel == null) || (seedForNextProvisionedReceiveKey == null)) {
                return null
            }
            try {
                val provision = Provision(
                    channelManagerSession,
                    fullRatchetingCount,
                    obliviousChannel,
                    seedForNextProvisionedReceiveKey,
                    obliviousEngineVersion
                )
                provision.insert()
                provision.selfRatchet(2 * Constants.REPROVISIONING_THRESHOLD)
                return provision
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
                            FULL_RATCHETING_COUNT + " INT NOT NULL, " +
                            SELF_RATCHETING_COUNT + " INT NOT NULL, " +
                            SEED_FOR_NEXT_PROVISIONED_RECEIVE_KEY + " BLOB NOT NULL, " +
                            OBLIVIOUS_ENGINE_VERSION + " INT NOT NULL, " +
                            OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " BLOB NOT NULL, " +
                            OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " BLOB NOT NULL, " +
                            OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + FULL_RATCHETING_COUNT + ", " + OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + ", " + OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + ", " + OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + "), " +
                            "FOREIGN KEY (" + OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + ", " + OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + ", " + OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + ") REFERENCES " + ObliviousChannel.TABLE_NAME + "(" + ObliviousChannel.CURRENT_DEVICE_UID + ", " + ObliviousChannel.REMOTE_DEVICE_UID + ", " + ObliviousChannel.REMOTE_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM provision AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM oblivious_channel " +
                                " WHERE current_device_uid = p.oblivious_channel_current_device_uid" +
                                " AND remote_device_uid = p.oblivious_channel_remote_device_uid" +
                                " AND contact_identity = p.oblivious_channel_remote_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
        }

        fun get(
            channelManagerSession: ChannelManagerSession,
            fullRatchetingCount: Int,
            obliviousChannelCurrentDeviceUid: UID?,
            obliviousChannelRemoteDeviceUid: UID?,
            obliviousChannelRemoteIdentity: Identity?
        ): Provision? {
            if ((obliviousChannelCurrentDeviceUid == null) || (obliviousChannelRemoteDeviceUid == null) || (obliviousChannelRemoteIdentity == null)) {
                return null
            }
            try {
                channelManagerSession.session.prepareStatement(
                    "Provision.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " +
                            FULL_RATCHETING_COUNT + " = ? AND " +
                            OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ? AND " +
                            OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = ? AND " +
                            OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, fullRatchetingCount)
                    statement.setBytes(2, obliviousChannelCurrentDeviceUid.bytes)
                    statement.setBytes(3, obliviousChannelRemoteDeviceUid.bytes)
                    statement.setBytes(4, obliviousChannelRemoteIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return Provision(channelManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }
    }
}
