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
package io.olvid.engine.identity.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.PreKeyBlobOnServer
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.PreKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types
import kotlin.collections.toTypedArray

class OwnedDevice : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val uid: UID
    private var ownedIdentity: Identity? = null
    @JvmField val isCurrentDevice: Boolean
    private var serializedDeviceCapabilities: ByteArray? // for the current device, this corresponds to the capabilities that were pushed to contacts. Actual capabilities are static in ObvCapability!
    private var displayName: String?
    var expirationTimestamp: Long?
        private set
    var lastRegistrationTimestamp: Long?
        private set
    private var latestChannelCreationPingTimestamp: Long
    private var preKeyId: KeyId? = null
    private var preKeyEncryptionPublicKey: EncryptionPublicKey? = null
    private var preKeyExpirationTimestamp: Long? = null

    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun hasPreKey(): Boolean {
        return preKeyId != null
    }


    @set:Throws(SQLException::class)
    var preKey: PreKey?
        get() {
            if (hasPreKey()) {
                return PreKey(uid, preKeyId, preKeyEncryptionPublicKey, preKeyExpirationTimestamp!!)
            } else {
                return null
            }
        }
        set(preKey) {
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.setPreKey",
                "UPDATE " + TABLE_NAME +
                        " SET " + PRE_KEY_ID + " = ?, " +
                        PRE_KEY_ENCRYPTION_PUBLIC_KEY + " = ?, " +
                        PRE_KEY_EXPIRATION_TIMESTAMP + " = ? " +
                        " WHERE " + UID_ + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                val preKeyAddedOrRemoved: Boolean
                if (preKey == null) {
                    statement.setNull(1, Types.BLOB)
                    statement.setNull(2, Types.BLOB)
                    statement.setNull(3, Types.BIGINT)
                    preKeyAddedOrRemoved = this.preKeyId != null
                    this.preKeyId = null
                    this.preKeyEncryptionPublicKey = null
                    this.preKeyExpirationTimestamp = null
                } else {
                    statement.setBytes(1, preKey.keyId!!.bytes)
                    statement.setBytes(
                        2,
                        Encoded.of(preKey.encryptionPublicKey!!).bytes
                    )
                    statement.setLong(3, preKey.expirationTimestamp)
                    preKeyAddedOrRemoved = this.preKeyId == null
                    this.preKeyId = preKey.keyId
                    this.preKeyEncryptionPublicKey = preKey.encryptionPublicKey
                    this.preKeyExpirationTimestamp = preKey.expirationTimestamp
                }
                statement.setBytes(4, uid.bytes)
                statement.setBytes(5, ownedIdentity!!.getBytes())
                statement.executeUpdate()
                if (preKeyAddedOrRemoved) {
                    commitHookBits =
                        commitHookBits or HOOK_BIT_DEVICES_CHANGED
                    identityManagerSession.session.addSessionCommitListener(this)
                }
            }
        }


    fun getDisplayName(): String? {
        return displayName
    }

    val deviceCapabilities: MutableList<ObvCapability>?
        get() = ObvCapability.deserializeDeviceCapabilities(serializedDeviceCapabilities)

    @set:Throws(SQLException::class)
    var rawDeviceCapabilities: Array<String>?
        get() = ObvCapability.deserializeRawDeviceCapabilities(serializedDeviceCapabilities)
        set(rawDeviceCapabilities) {
            val serializedDeviceCapabilities =
                ObvCapability.serializeRawDeviceCapabilities(rawDeviceCapabilities)
            if (serializedDeviceCapabilities.contentEquals(this.serializedDeviceCapabilities)) {
                // if the capabilities did not change, do not update/notify
                return
            }

            identityManagerSession.session.prepareStatement(
                "OwnedDevice.setRawDeviceCapabilities",
                "UPDATE " + TABLE_NAME +
                        " SET " + SERIALIZED_DEVICE_CAPABILITIES + " = ? " +
                        " WHERE " + UID_ + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, serializedDeviceCapabilities)
                statement.setBytes(2, this.uid.bytes)
                statement.setBytes(3, this.ownedIdentity!!.getBytes())
                statement.executeUpdate()
                this.serializedDeviceCapabilities = serializedDeviceCapabilities
                commitHookBits =
                    commitHookBits or HOOK_BIT_CAPABILITIES_UPDATED
                identityManagerSession.session.addSessionCommitListener(this)
            }
        }

    fun getLatestChannelCreationPingTimestamp(): Long {
        return latestChannelCreationPingTimestamp
    }

    private constructor(
        identityManagerSession: IdentityManagerSession,
        uid: UID,
        ownedIdentity: Identity,
        isCurrentDevice: Boolean,
        serializedDeviceCapabilities: ByteArray?,
        displayName: String?,
        expirationTimestamp: Long?,
        lastRegistrationTimestamp: Long?,
        preKey: PreKey?
    ) {
        this.identityManagerSession = identityManagerSession
        this.uid = uid
        this.ownedIdentity = ownedIdentity
        this.isCurrentDevice = isCurrentDevice
        this.serializedDeviceCapabilities = serializedDeviceCapabilities
        this.displayName = displayName
        this.expirationTimestamp = expirationTimestamp
        this.lastRegistrationTimestamp = lastRegistrationTimestamp
        this.latestChannelCreationPingTimestamp = 0
        if (preKey != null) {
            this.preKeyId = preKey.keyId
            this.preKeyEncryptionPublicKey = preKey.encryptionPublicKey
            this.preKeyExpirationTimestamp = preKey.expirationTimestamp
        }
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.uid = UID(res.getBytes(UID_))
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.isCurrentDevice = res.getBoolean(IS_CURRENT_DEVICE)
        this.serializedDeviceCapabilities = res.getBytes(SERIALIZED_DEVICE_CAPABILITIES)
        this.displayName = res.getString(DISPLAY_NAME)
        this.expirationTimestamp = res.getLong(EXPIRATION_TIMESTAMP)
        if (res.wasNull()) {
            this.expirationTimestamp = null
        }
        this.lastRegistrationTimestamp = res.getLong(LAST_REGISTRATION_TIMESTAMP)
        if (res.wasNull()) {
            this.lastRegistrationTimestamp = null
        }
        this.latestChannelCreationPingTimestamp =
            res.getLong(LATEST_CHANNEL_CREATION_PING_TIMESTAMP)
        val preKeyIdBytes: ByteArray? = res.getBytes(PRE_KEY_ID)
        this.preKeyId = if (preKeyIdBytes == null) null else KeyId(preKeyIdBytes)
        val preKeyEncodedPublicKeyBytes: ByteArray? = res.getBytes(PRE_KEY_ENCRYPTION_PUBLIC_KEY)
        if (preKeyEncodedPublicKeyBytes != null) {
            try {
                this.preKeyEncryptionPublicKey =
                    Encoded(preKeyEncodedPublicKeyBytes).decodePublicKey() as EncryptionPublicKey?
            } catch (_: DecodingException) {
            }
        }
        this.preKeyExpirationTimestamp = res.getLong(PRE_KEY_EXPIRATION_TIMESTAMP)
        if (res.wasNull()) {
            this.preKeyExpirationTimestamp = null
        }
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "OwnedDevice.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?);"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setBoolean(3, isCurrentDevice)
            statement.setBytes(4, serializedDeviceCapabilities)
            statement.setString(5, displayName)

            if (expirationTimestamp == null) {
                statement.setNull(6, Types.INTEGER)
            } else {
                statement.setLong(6, expirationTimestamp!!)
            }
            if (lastRegistrationTimestamp == null) {
                statement.setNull(7, Types.INTEGER)
            } else {
                statement.setLong(7, lastRegistrationTimestamp!!)
            }
            statement.setLong(8, latestChannelCreationPingTimestamp)


            if (preKeyId != null && preKeyEncryptionPublicKey != null && preKeyExpirationTimestamp != null) {
                statement.setBytes(9, preKeyId!!.bytes)
                statement.setBytes(10, Encoded.of(preKeyEncryptionPublicKey!!).bytes)
                statement.setLong(11, preKeyExpirationTimestamp!!)
            } else {
                statement.setBytes(9, null)
                statement.setBytes(10, null)
                statement.setNull(11, Types.BIGINT)
            }

            statement.executeUpdate()
            if (!isCurrentDevice) {
                commitHookBits =
                    commitHookBits or (HOOK_BIT_INSERTED_OTHER_DEVICE or HOOK_BIT_DEVICES_CHANGED)
                identityManagerSession.session.addSessionCommitListener(this)
            }
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "OwnedDevice.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.executeUpdate()
            commitHookBits =
                commitHookBits or (HOOK_BIT_CAPABILITIES_UPDATED or HOOK_BIT_DEVICES_CHANGED)
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }


    @Throws(SQLException::class)
    fun setDisplayName(displayName: String?) {
        identityManagerSession.session.prepareStatement(
            "OwnedDevice.setDisplayName",
            "UPDATE " + TABLE_NAME +
                    " SET " + DISPLAY_NAME + " = ? " +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, displayName)
            statement.setBytes(2, this.uid.bytes)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.displayName = displayName
            commitHookBits = commitHookBits or HOOK_BIT_DEVICES_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setLatestChannelCreationPingTimestamp(timestamp: Long) {
        identityManagerSession.session.prepareStatement(
            "OwnedDevice.setLatestChannelCreationPingTimestamp",
            "UPDATE " + TABLE_NAME +
                    " SET " + LATEST_CHANNEL_CREATION_PING_TIMESTAMP + " = ? " +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setLong(1, timestamp)
            statement.setBytes(2, this.uid.bytes)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.latestChannelCreationPingTimestamp = timestamp
        }
    }

    @Throws(SQLException::class)
    fun setTimestamps(expirationTimestamp: Long?, lastRegistrationTimestamp: Long?) {
        identityManagerSession.session.prepareStatement(
            "OwnedDevice.setTimestamps",
            "UPDATE " + TABLE_NAME +
                    " SET " + EXPIRATION_TIMESTAMP + " = ?, " +
                    LAST_REGISTRATION_TIMESTAMP + " = ? " +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            if (expirationTimestamp == null) {
                statement.setNull(1, Types.INTEGER)
            } else {
                statement.setLong(1, expirationTimestamp)
            }
            if (lastRegistrationTimestamp == null) {
                statement.setNull(2, Types.INTEGER)
            } else {
                statement.setLong(2, lastRegistrationTimestamp)
            }
            statement.setBytes(3, this.uid.bytes)
            statement.setBytes(4, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.expirationTimestamp = expirationTimestamp
            this.lastRegistrationTimestamp = lastRegistrationTimestamp
            commitHookBits = commitHookBits or HOOK_BIT_DEVICES_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }


    @JvmField var channelCreationAlreadyInProgress: Boolean = false
    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        // this notification is only caught in the ChannelManager, to create a new channel
        if ((commitHookBits and HOOK_BIT_INSERTED_OTHER_DEVICE) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE_DEVICE_UID_KEY, uid)
            userInfo.put(
                IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE_OWNED_IDENTITY_KEY,
                ownedIdentity!!
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE_CHANNEL_CREATION_ALREADY_IN_PROGRESS_KEY,
                channelCreationAlreadyInProgress
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_NEW_OWNED_DEVICE,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_CAPABILITIES_UPDATED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_OWN_CAPABILITIES_UPDATED_OWNED_IDENTITY_KEY,
                ownedIdentity!!
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_OWN_CAPABILITIES_UPDATED,
                userInfo
            )
        }
        // this notification is propagated to the App
        if ((commitHookBits and HOOK_BIT_DEVICES_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_OWNED_DEVICE_LIST_CHANGED_OWNED_IDENTITY_KEY,
                ownedIdentity!!
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_OWNED_DEVICE_LIST_CHANGED,
                userInfo
            )
        }
        commitHookBits = 0
    }

    companion object {
        const val TABLE_NAME: String = "owned_device"

        const val UID_: String = "uid"
        const val OWNED_IDENTITY: String = "identity"
        const val IS_CURRENT_DEVICE: String = "is_current_device"
        const val SERIALIZED_DEVICE_CAPABILITIES: String = "serialized_device_capabilities"

        const val DISPLAY_NAME: String = "display_name"
        const val EXPIRATION_TIMESTAMP: String = "expiration_timestamp"
        const val LAST_REGISTRATION_TIMESTAMP: String = "last_registration_timestamp"
        const val LATEST_CHANNEL_CREATION_PING_TIMESTAMP: String =
            "latest_channel_creation_ping_timestamp"
        const val PRE_KEY_ID: String = "pre_key_id"
        const val PRE_KEY_ENCRYPTION_PUBLIC_KEY: String = "pre_key_encryption_public_key"
        const val PRE_KEY_EXPIRATION_TIMESTAMP: String = "pre_key_expiration_timestamp"


        fun createOtherDevice(
            identityManagerSession: IdentityManagerSession,
            uid: UID,
            identity: Identity?,
            displayName: String?,
            expirationTimestamp: Long?,
            lastRegistrationTimestamp: Long?,
            preKeyBlob: PreKeyBlobOnServer?,
            channelCreationAlreadyInProgress: Boolean
        ): OwnedDevice? {
            if (identity == null) {
                return null
            }
            try {
                val ownedDevice = OwnedDevice(
                    identityManagerSession,
                    uid,
                    identity,
                    false,
                    if (preKeyBlob == null) null else ObvCapability.serializeRawDeviceCapabilities(
                        preKeyBlob.rawDeviceCapabilities
                    ),
                    displayName,
                    expirationTimestamp,
                    lastRegistrationTimestamp,
                    if (preKeyBlob == null) null else preKeyBlob.preKey
                )
                ownedDevice.insert()
                ownedDevice.channelCreationAlreadyInProgress = channelCreationAlreadyInProgress
                return ownedDevice
            } catch (_: SQLException) {
                return null
            }
        }

        fun createCurrentDevice(
            identityManagerSession: IdentityManagerSession,
            identity: Identity?,
            displayName: String?,
            prng: PRNGService
        ): OwnedDevice? {
            if (identity == null) {
                return null
            }
            val uid = UID(prng)
            try {
                val ownedDevice = OwnedDevice(
                    identityManagerSession,
                    uid,
                    identity,
                    true,
                    null,
                    displayName,
                    null,
                    null,
                    null
                )
                ownedDevice.insert()
                return ownedDevice
            } catch (_: SQLException) {
                return null
            }
        }

        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            UID_ + " BLOB PRIMARY KEY, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            IS_CURRENT_DEVICE + " BIT NOT NULL, " +
                            SERIALIZED_DEVICE_CAPABILITIES + " BLOB DEFAULT NULL, " +
                            DISPLAY_NAME + " TEXT DEFAULT NULL, " +
                            EXPIRATION_TIMESTAMP + " INTEGER DEFAULT NULL, " +
                            LAST_REGISTRATION_TIMESTAMP + " INTEGER DEFAULT NULL, " +
                            LATEST_CHANNEL_CREATION_PING_TIMESTAMP + " BIGINT NOT NULL DEFAULT 0, " +
                            PRE_KEY_ID + " BLOB DEFAULT NULL, " +
                            PRE_KEY_ENCRYPTION_PUBLIC_KEY + " BLOB DEFAULT NULL, " +
                            PRE_KEY_EXPIRATION_TIMESTAMP + " BIGINT DEFAULT NULL, " +
                            "FOREIGN KEY (" + OWNED_IDENTITY + ") REFERENCES " + OwnedIdentity.TABLE_NAME + " (" + OwnedIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 27 && newVersion >= 27) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `serialized_device_capabilities` BLOB DEFAULT NULL")
                }
                oldVersion = 27
            }
            if (oldVersion < 35 && newVersion >= 35) {
                Logger.d("MIGRATING `owned_device` DATABASE FROM VERSION " + oldVersion + " TO 35")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `display_name` TEXT DEFAULT NULL")
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `expiration_timestamp` INTEGER DEFAULT NULL")
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `last_registration_timestamp` INTEGER DEFAULT NULL")
                }
                oldVersion = 35
            }
            if (oldVersion < 41 && newVersion >= 41) {
                Logger.d("MIGRATING `owned_device` DATABASE FROM VERSION " + oldVersion + " TO 41")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `latest_channel_creation_ping_timestamp` BIGINT NOT NULL DEFAULT 0")
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `pre_key_id` BLOB DEFAULT NULL")
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `pre_key_encryption_public_key` BLOB DEFAULT NULL")
                    statement.execute("ALTER TABLE owned_device ADD COLUMN `pre_key_expiration_timestamp` BIGINT DEFAULT NULL")
                }
                oldVersion = 41
            }
        }

        @Throws(SQLException::class)
        fun get(identityManagerSession: IdentityManagerSession, ownedDeviceUid: UID): OwnedDevice? {
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " +
                        UID_ + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedDeviceUid.bytes)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OwnedDevice(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }


        @Throws(SQLException::class)
        fun getCurrentDeviceOfOwnedIdentity(
            identityManagerSession: IdentityManagerSession,
            identity: Identity?
        ): OwnedDevice? {
            if ((identity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.getCurrentDeviceOfOwnedIdentity",
                "SELECT * FROM " + TABLE_NAME + " WHERE " +
                        OWNED_IDENTITY + " = ? AND " +
                        IS_CURRENT_DEVICE + " = 1;"
            ).use { statement ->
                statement.setBytes(1, identity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OwnedDevice(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getOtherDevicesOfOwnedIdentity(
            identityManagerSession: IdentityManagerSession,
            identity: Identity
        ): Array<OwnedDevice> {
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.getOtherDevicesOfOwnedIdentity",
                "SELECT * FROM " + TABLE_NAME + " WHERE " +
                        OWNED_IDENTITY + " = ? AND " +
                        IS_CURRENT_DEVICE + " = 0;"
            ).use { statement ->
                statement.setBytes(1, identity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<OwnedDevice> = ArrayList()
                    while (res.next()) {
                        list.add(OwnedDevice(identityManagerSession, res))
                    }
                    return list.toTypedArray<OwnedDevice>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllDevicesOfIdentity(
            identityManagerSession: IdentityManagerSession,
            identity: Identity
        ): MutableList<OwnedDevice> {
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.getAllDevicesOfIdentity",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, identity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<OwnedDevice> = ArrayList()
                    while (res.next()) {
                        list.add(OwnedDevice(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithExpiredPreKey(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            expirationTimestamp: Long
        ): MutableList<OwnedDevice> {
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.getAllWithExpiredPreKey",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + PRE_KEY_EXPIRATION_TIMESTAMP + " < ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setLong(2, expirationTimestamp)
                statement.executeQuery().use { res ->
                    val list: MutableList<OwnedDevice> = ArrayList()
                    while (res.next()) {
                        list.add(OwnedDevice(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllDeviceUidsOfIdentity(
            identityManagerSession: IdentityManagerSession,
            identity: Identity
        ): Array<UID?> {
            identityManagerSession.session.prepareStatement(
                "OwnedDevice.getAllDeviceUidsOfIdentity",
                "SELECT " + UID_ + " FROM " + TABLE_NAME + " WHERE " +
                        OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, identity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<UID?> = ArrayList<UID?>()
                    while (res.next()) {
                        list.add(UID(res.getBytes(UID_)))
                    }
                    return list.toTypedArray<UID?>()
                }
            }
        }

        private const val HOOK_BIT_INSERTED_OTHER_DEVICE: Long = 0x1
        private const val HOOK_BIT_CAPABILITIES_UPDATED: Long = 0x2
        private const val HOOK_BIT_DEVICES_CHANGED: Long = 0x4
    }
}
