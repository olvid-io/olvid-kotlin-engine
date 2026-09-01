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
package io.olvid.engine.networkfetch.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class PushNotificationConfiguration : ObvDatabase {
    private val fetchManagerSession: FetchManagerSession

    private var ownedIdentity: Identity? = null
    @JvmField val deviceUid: UID
    @JvmField val pushNotificationType: Byte
    @JvmField val token: ByteArray?
    @JvmField val identityMaskingUid: UID?
    private var multiDeviceConfiguration: Int
    @JvmField val deviceUidToReplace: UID?

    //    private static final int CONFIGURATION_USE_MULTI_DEVICE_BIT = 0x2;
    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun shouldReactivateCurrentDevice(): Boolean {
        return (multiDeviceConfiguration and CONFIGURATION_REACTIVATE_CURRENT_DEVICE_AT_NEXT_REGISTRATION_BIT) != 0
    }

    val pushNotificationTypeAndParameters: PushNotificationTypeAndParameters
        get() {
            val reactivateCurrentDevice =
                (multiDeviceConfiguration and CONFIGURATION_REACTIVATE_CURRENT_DEVICE_AT_NEXT_REGISTRATION_BIT) != 0
            return PushNotificationTypeAndParameters(
                pushNotificationType,
                token,
                identityMaskingUid,
                reactivateCurrentDevice,
                deviceUidToReplace
            )
        }

    private constructor(
        fetchManagerSession: FetchManagerSession,
        ownedIdentity: Identity,
        deviceUid: UID,
        pushNotificationType: Byte,
        token: ByteArray?,
        identityMaskingUid: UID?,
        multiDeviceConfiguration: Int,
        deviceUidToReplace: UID?
    ) {
        this.fetchManagerSession = fetchManagerSession
        this.ownedIdentity = ownedIdentity
        this.deviceUid = deviceUid
        this.pushNotificationType = pushNotificationType
        this.token = token
        this.identityMaskingUid = identityMaskingUid
        this.multiDeviceConfiguration = multiDeviceConfiguration
        this.deviceUidToReplace = deviceUidToReplace
    }

    private constructor(fetchManagerSession: FetchManagerSession, res: ResultSet) {
        this.fetchManagerSession = fetchManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.deviceUid = UID(res.getBytes(DEVICE_UID))
        this.pushNotificationType = res.getByte(PUSH_NOTIFICATION_TYPE)
        this.token = res.getBytes(TOKEN)
        val identityMaskingBytes: ByteArray? = res.getBytes(IDENTITY_MASKING_UID)
        this.identityMaskingUid =
            if (identityMaskingBytes == null) null else UID(identityMaskingBytes)
        this.multiDeviceConfiguration = res.getInt(MULTI_DEVICE_CONFIGURATION)
        val bytesDeviceUidToReplace: ByteArray? = res.getBytes(DEVICE_UID_TO_REPLACE)
        this.deviceUidToReplace =
            if (bytesDeviceUidToReplace == null) null else UID(bytesDeviceUidToReplace)
    }

    @Throws(SQLException::class)
    override fun insert() {
        fetchManagerSession.session.prepareStatement(
            "PushNotificationConfiguration.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES(?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, deviceUid.bytes)
            statement.setByte(3, pushNotificationType)
            statement.setBytes(4, token)
            statement.setBytes(
                5,
                if (identityMaskingUid == null) null else identityMaskingUid.bytes
            )
            statement.setInt(6, multiDeviceConfiguration)
            statement.setBytes(
                7,
                if (deviceUidToReplace == null) null else deviceUidToReplace.bytes
            )
            statement.executeUpdate()
            this.commitHookBits = this.commitHookBits or HOOK_BIT_INSERT
            fetchManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        fetchManagerSession.session.prepareStatement(
            "PushNotificationConfiguration.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.executeUpdate()
        }
    }

    // endregion
    // region setters
    fun clearKickOtherDevices() {
        try {
            fetchManagerSession.session.prepareStatement(
                "PushNotificationConfiguration.clearKickOtherDevices",
                "UPDATE " + TABLE_NAME +
                        " SET " + MULTI_DEVICE_CONFIGURATION + " = ?, " +
                        DEVICE_UID_TO_REPLACE + " = NULL " +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                val newMultiDeviceConfiguration =
                    multiDeviceConfiguration and (CONFIGURATION_REACTIVATE_CURRENT_DEVICE_AT_NEXT_REGISTRATION_BIT.inv())
                statement.setInt(1, newMultiDeviceConfiguration)
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.executeUpdate()
                this.multiDeviceConfiguration = newMultiDeviceConfiguration
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    // endregion
    // region hooks
    interface NewPushNotificationConfigurationListener {
        fun newPushNotificationConfiguration(
            identity: Identity?,
            deviceUid: UID?,
            pushNotificationTypeAndParameters: PushNotificationTypeAndParameters?
        )
    }

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERT) != 0L) {
            if (fetchManagerSession.newPushNotificationConfigurationListener != null) {
                fetchManagerSession.newPushNotificationConfigurationListener.newPushNotificationConfiguration(
                    ownedIdentity, deviceUid,
                    this.pushNotificationTypeAndParameters
                )
            }
        }
    } // endregion

    companion object {
        const val TABLE_NAME: String = "push_notification_configuration"


        const val OWNED_IDENTITY: String = "identity"
        const val DEVICE_UID: String = "device_uid"
        const val PUSH_NOTIFICATION_TYPE: String = "push_notification_type"
        const val TOKEN: String = "token"
        const val IDENTITY_MASKING_UID: String = "identity_masking_uid"
        const val MULTI_DEVICE_CONFIGURATION: String = "multi_device_configuration"
        const val DEVICE_UID_TO_REPLACE: String = "device_uid_to_replace"


        private const val CONFIGURATION_REACTIVATE_CURRENT_DEVICE_AT_NEXT_REGISTRATION_BIT = 0x1

        // region constructors
        fun create(
            fetchManagerSession: FetchManagerSession?,
            ownedIdentity: Identity?,
            deviceUid: UID?,
            pushNotificationTypeAndParameters: PushNotificationTypeAndParameters?
        ): PushNotificationConfiguration? {
            if (ownedIdentity == null || deviceUid == null || pushNotificationTypeAndParameters == null) {
                return null
            }

            var multiDeviceConfiguration = 0
            if (pushNotificationTypeAndParameters.reactivateCurrentDevice) {
                multiDeviceConfiguration =
                    multiDeviceConfiguration or CONFIGURATION_REACTIVATE_CURRENT_DEVICE_AT_NEXT_REGISTRATION_BIT
            }

            try {
                val pushNotificationConfiguration = PushNotificationConfiguration(
                    fetchManagerSession!!,
                    ownedIdentity,
                    deviceUid,
                    pushNotificationTypeAndParameters.pushNotificationType,
                    pushNotificationTypeAndParameters.token,
                    pushNotificationTypeAndParameters.identityMaskingUid,
                    multiDeviceConfiguration,
                    pushNotificationTypeAndParameters.deviceUidToReplace
                )
                pushNotificationConfiguration.insert()
                return pushNotificationConfiguration
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
                            OWNED_IDENTITY + " BLOB PRIMARY KEY, " +
                            DEVICE_UID + " BLOB NOT NULL, " +
                            PUSH_NOTIFICATION_TYPE + " INT NOT NULL, " +
                            TOKEN + " BLOB, " +
                            IDENTITY_MASKING_UID + " BLOB, " +
                            MULTI_DEVICE_CONFIGURATION + " INT NOT NULL," +
                            DEVICE_UID_TO_REPLACE + " BLOB " +
                            ");"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 15 && newVersion >= 15) {
                Logger.d("DELETING old `registered_push_notification` table. It is replaced by the new and better `push_notification_configuration`.")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE IF EXISTS registered_push_notification")
                }
                oldVersion = 15
            }
            if (oldVersion < 35 && newVersion >= 35) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `push_notification_configuration` TABLE FROM VERSION " + oldVersion + " TO 35")
                    statement.execute("ALTER TABLE push_notification_configuration ADD COLUMN device_uid_to_replace BLOB DEFAULT NULL")
                }
                oldVersion = 35
            }
        }

        // endregion
        // region getters
        fun get(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?
        ): PushNotificationConfiguration? {
            if (ownedIdentity == null) {
                return null
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "PushNotificationConfiguration.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return PushNotificationConfiguration(fetchManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        fun getAll(fetchManagerSession: FetchManagerSession): Array<PushNotificationConfiguration?> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "PushNotificationConfiguration.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<PushNotificationConfiguration?> =
                            ArrayList<PushNotificationConfiguration?>()
                        while (res.next()) {
                            list.add(PushNotificationConfiguration(fetchManagerSession, res))
                        }
                        return list.toTypedArray<PushNotificationConfiguration?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<PushNotificationConfiguration>(0)
            }
        }

        @Throws(SQLException::class)
        fun deleteForOwnedIdentity(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity
        ) {
            fetchManagerSession.session.prepareStatement(
                "PushNotificationConfiguration.deleteForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        private const val HOOK_BIT_INSERT: Long = 0x1
    }
}
