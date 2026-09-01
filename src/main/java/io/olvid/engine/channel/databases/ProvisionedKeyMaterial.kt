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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types

class ProvisionedKeyMaterial : ObvDatabase {
    private val channelManagerSession: ChannelManagerSession

    private val keyId: KeyId
    @JvmField val authEncKey: AuthEncKey?
    private val expirationTimestamp: Long?
    @JvmField val selfRatchetingCount: Int

    // foreign key for a Provision
    @JvmField val provisionFullRatchetingCount: Int
    @JvmField val provisionObliviousChannelCurrentDeviceUid: UID
    @JvmField val provisionObliviousChannelRemoteDeviceUid: UID
    @JvmField val provisionObliviousChannelRemoteIdentity: Identity

    val obliviousChannel: ObliviousChannel?
        //    public Provision getProvision() {
        get() = ObliviousChannel.get(
            channelManagerSession,
            provisionObliviousChannelCurrentDeviceUid,
            provisionObliviousChannelRemoteDeviceUid,
            provisionObliviousChannelRemoteIdentity,
            false
        )


    fun setExpirationTimestampsOfOlderProvisionedKeyMaterials() {
        try {
            channelManagerSession.session.prepareStatement(
                "ProvisionedKeyMaterial.setExpirationTimestampsOfOlderProvisionedKeyMaterials",
                "UPDATE " + TABLE_NAME + " SET " +
                        EXPIRATION_TIMESTAMP + " = ? " +
                        " WHERE " + EXPIRATION_TIMESTAMP + " IS NULL AND " +
                        PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ? AND " +
                        PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = ? AND " +
                        PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = ? AND " +
                        "( " + PROVISION_FULL_RATCHETING_COUNT + " < ? OR " +
                        "( " + PROVISION_FULL_RATCHETING_COUNT + " = ? AND " +
                        SELF_RATCHETING_COUNT + " < ?));"
            ).use { statement ->
                val expirationTimestamp =
                    System.currentTimeMillis() + Constants.PROVISIONED_KEY_MATERIAL_EXPIRATION_DELAY
                statement.setLong(1, expirationTimestamp)
                statement.setBytes(2, provisionObliviousChannelCurrentDeviceUid.bytes)
                statement.setBytes(3, provisionObliviousChannelRemoteDeviceUid.bytes)
                statement.setBytes(4, provisionObliviousChannelRemoteIdentity.getBytes())
                statement.setInt(5, provisionFullRatchetingCount)
                statement.setInt(6, provisionFullRatchetingCount)
                statement.setInt(7, selfRatchetingCount)
                statement.executeUpdate()
            }
        } catch (_: SQLException) {
        }
    }

    private constructor(
        channelManagerSession: ChannelManagerSession,
        keyId: KeyId,
        authEncKey: AuthEncKey,
        selfRatchetingCount: Int,
        provision: Provision
    ) {
        this.channelManagerSession = channelManagerSession
        this.keyId = keyId
        this.authEncKey = authEncKey
        this.expirationTimestamp = null
        this.selfRatchetingCount = selfRatchetingCount
        this.provisionFullRatchetingCount = provision.fullRatchetingCount
        this.provisionObliviousChannelCurrentDeviceUid =
            provision.obliviousChannelCurrentDeviceUid
        this.provisionObliviousChannelRemoteDeviceUid =
            provision.obliviousChannelRemoteDeviceUid
        this.provisionObliviousChannelRemoteIdentity = provision.obliviousChannelRemoteIdentity
    }

    private constructor(channelManagerSession: ChannelManagerSession, res: ResultSet) {
        this.channelManagerSession = channelManagerSession
        this.keyId = KeyId(res.getBytes(KEY_ID))
        var key: AuthEncKey? = null
        try {
            key = Encoded(res.getBytes(AUTH_ENC_KEY)).decodeSymmetricKey() as AuthEncKey?
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.authEncKey = key
        this.expirationTimestamp = res.getLong(EXPIRATION_TIMESTAMP)
        this.selfRatchetingCount = res.getInt(SELF_RATCHETING_COUNT)
        this.provisionFullRatchetingCount = res.getInt(PROVISION_FULL_RATCHETING_COUNT)
        this.provisionObliviousChannelCurrentDeviceUid = UID(
            res.getBytes(
                PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID
            )
        )
        this.provisionObliviousChannelRemoteDeviceUid = UID(
            res.getBytes(
                PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID
            )
        )
        try {
            this.provisionObliviousChannelRemoteIdentity = Identity.of(
                res.getBytes(
                    PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY
                )
            )
        } catch (_: DecodingException) {
            throw SQLException()
        }
    }


    @Throws(SQLException::class)
    override fun insert() {
        channelManagerSession.session.prepareStatement(
            "ProvisionedKeyMaterial.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?);"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.setBytes(2, Encoded.of(authEncKey!!).bytes)
            if (expirationTimestamp == null) {
                statement.setNull(3, Types.BIGINT)
            } else {
                statement.setLong(3, expirationTimestamp)
            }
            statement.setInt(4, selfRatchetingCount)
            statement.setInt(5, provisionFullRatchetingCount)
            statement.setBytes(6, provisionObliviousChannelCurrentDeviceUid.bytes)
            statement.setBytes(7, provisionObliviousChannelRemoteDeviceUid.bytes)
            statement.setBytes(8, provisionObliviousChannelRemoteIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        channelManagerSession.session.prepareStatement(
            "ProvisionedKeyMaterial.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + SELF_RATCHETING_COUNT + " = ? AND " + PROVISION_FULL_RATCHETING_COUNT + " = ? AND " + PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ? AND " + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = ? AND " + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, selfRatchetingCount)
            statement.setInt(2, provisionFullRatchetingCount)
            statement.setBytes(3, provisionObliviousChannelCurrentDeviceUid.bytes)
            statement.setBytes(4, provisionObliviousChannelRemoteDeviceUid.bytes)
            statement.setBytes(5, provisionObliviousChannelRemoteIdentity.getBytes())
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // no hooks here
    }

    companion object {
        const val TABLE_NAME: String = "provisioned_key_material"
        const val GET_ALL_INDEX_NAME: String = "provisioned_key_material_get_all_index"
        const val EXPIRE_INDEX_NAME: String = "provisioned_key_material_expire_index"


        const val KEY_ID: String = "key_id"
        const val AUTH_ENC_KEY: String = "auth_enc_key"
        const val EXPIRATION_TIMESTAMP: String = "expiration_timestamp"
        const val SELF_RATCHETING_COUNT: String = "self_ratcheting_count"

        const val PROVISION_FULL_RATCHETING_COUNT: String = "provision_full_ratcheting_count"
        const val PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID: String =
            "provision_oblivious_channel_current_device_uid"
        const val PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID: String =
            "provision_oblivious_channel_remote_device_uid"
        const val PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY: String =
            "provision_oblivious_channel_remote_identity"


        fun deleteAllExpired(channelManagerSession: ChannelManagerSession) {
            try {
                channelManagerSession.session.prepareStatement(
                    "ProvisionedKeyMaterial.deleteAllExpired",
                    "DELETE FROM " + TABLE_NAME + " WHERE " + EXPIRATION_TIMESTAMP + " IS NOT NULL AND " + EXPIRATION_TIMESTAMP + " < ?;"
                ).use { statement ->
                    statement.setLong(1, System.currentTimeMillis())
                    statement.executeUpdate()
                }
            } catch (_: SQLException) {
            }
        }


        fun create(
            channelManagerSession: ChannelManagerSession,
            keyId: KeyId?,
            authEncKey: AuthEncKey?,
            selfRatchetingCount: Int,
            provision: Provision?
        ): ProvisionedKeyMaterial? {
            if ((keyId == null) || (authEncKey == null) || (provision == null)) {
                return null
            }
            try {
                val provisionedKeyMaterial = ProvisionedKeyMaterial(
                    channelManagerSession,
                    keyId,
                    authEncKey,
                    selfRatchetingCount,
                    provision
                )
                provisionedKeyMaterial.insert()
                return provisionedKeyMaterial
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
                            KEY_ID + " BLOB NOT NULL, " +
                            AUTH_ENC_KEY + " BLOB NOT NULL, " +
                            EXPIRATION_TIMESTAMP + " BIGINT, " +
                            SELF_RATCHETING_COUNT + " INT NOT NULL, " +
                            PROVISION_FULL_RATCHETING_COUNT + " INT NOT NULL, " +
                            PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " BLOB NOT NULL, " +
                            PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " BLOB NOT NULL, " +
                            PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " BLOB NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + SELF_RATCHETING_COUNT + ", " + PROVISION_FULL_RATCHETING_COUNT + ", " + PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + ", " + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + ", " + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + "), " +
                            "FOREIGN KEY (" + PROVISION_FULL_RATCHETING_COUNT + ", " + PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + ", " + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + ", " + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + ") REFERENCES " + Provision.TABLE_NAME + "(" + Provision.FULL_RATCHETING_COUNT + ", " + Provision.OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + ", " + Provision.OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + ", " + Provision.OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + ") ON DELETE CASCADE);"
                )
                statement.execute("CREATE INDEX IF NOT EXISTS " + GET_ALL_INDEX_NAME + " ON " + TABLE_NAME + "(" + KEY_ID + "," + PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + ")")
                statement.execute("CREATE INDEX IF NOT EXISTS " + EXPIRE_INDEX_NAME + " ON " + TABLE_NAME + "(" + EXPIRATION_TIMESTAMP + "," + PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + "," + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + "," + PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + ")")
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM provisioned_key_material AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM provision " +
                                " WHERE full_ratcheting_count = p.provision_full_ratcheting_count" +
                                " AND oblivious_channel_current_device_uid = p.provision_oblivious_channel_current_device_uid" +
                                " AND oblivious_channel_remote_device_uid = p.provision_oblivious_channel_remote_device_uid" +
                                " AND oblivious_channel_remote_identity = p.provision_oblivious_channel_remote_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
        }

        fun getAll(
            channelManagerSession: ChannelManagerSession,
            keyId: KeyId?,
            currentDeviceUid: UID?
        ): Array<ProvisionedKeyMaterial?> {
            if ((keyId == null) || (currentDeviceUid == null)) {
                return arrayOfNulls(0)
            }
            try {
                channelManagerSession.session.prepareStatement(
                    "ProvisionedKeyMaterial.getAll",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " +
                            KEY_ID + " = ? AND " +
                            PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, keyId.bytes)
                    statement.setBytes(2, currentDeviceUid.bytes)
                    statement.executeQuery().use { res ->
                        val list: MutableList<ProvisionedKeyMaterial?> =
                            ArrayList()
                        while (res.next()) {
                            list.add(ProvisionedKeyMaterial(channelManagerSession, res))
                        }
                        return list.toTypedArray<ProvisionedKeyMaterial?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls(0)
            }
        }


        fun countNotExpiringProvisionedReceiveKey(
            channelManagerSession: ChannelManagerSession,
            provision: Provision
        ): Int {
            val COUNT = "count"
            try {
                channelManagerSession.session.prepareStatement(
                    "ProvisionedKeyMaterial.countNotExpiringProvisionedReceiveKey",
                    "SELECT COUNT(*) AS " + COUNT + " FROM " + TABLE_NAME + " WHERE " +
                            EXPIRATION_TIMESTAMP + " IS NULL AND " +
                            PROVISION_FULL_RATCHETING_COUNT + " = ? AND " +
                            PROVISION_OBLIVIOUS_CHANNEL_CURRENT_DEVICE_UID + " = ? AND " +
                            PROVISION_OBLIVIOUS_CHANNEL_REMOTE_DEVICE_UID + " = ? AND " +
                            PROVISION_OBLIVIOUS_CHANNEL_REMOTE_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, provision.fullRatchetingCount)
                    statement.setBytes(2, provision.obliviousChannelCurrentDeviceUid.bytes)
                    statement.setBytes(3, provision.obliviousChannelRemoteDeviceUid.bytes)
                    statement.setBytes(4, provision.obliviousChannelRemoteIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        return if (res.next()) {
                            res.getInt(COUNT)
                        } else {
                            0
                        }
                    }
                }
            } catch (_: SQLException) {
                return 0
            }
        }
    }
}
