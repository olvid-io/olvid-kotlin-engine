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

class ContactDevice : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val uid: UID
    private var contactIdentity: Identity
    private var ownedIdentity: Identity
    private var serializedDeviceCapabilities: ByteArray?
    private var latestChannelCreationPingTimestamp: Long
    private var preKeyId: KeyId? = null
    private var preKeyEncryptionPublicKey: EncryptionPublicKey? = null
    private var preKeyExpirationTimestamp: Long? = null

    fun getContactIdentity(): Identity {
        return contactIdentity
    }

    fun getOwnedIdentity(): Identity {
        return ownedIdentity
    }

    val rawDeviceCapabilities: Array<String>
        get() = ObvCapability.deserializeRawDeviceCapabilities(serializedDeviceCapabilities)

    val deviceCapabilities: MutableList<ObvCapability>?
        get() = ObvCapability.deserializeDeviceCapabilities(serializedDeviceCapabilities)

    fun hasPreKey(): Boolean {
        return preKeyId != null
    }

    fun getLatestChannelCreationPingTimestamp(): Long {
        return latestChannelCreationPingTimestamp
    }

    val preKey: PreKey?
        get() {
            return if (hasPreKey()) {
                PreKey(uid, preKeyId, preKeyEncryptionPublicKey, preKeyExpirationTimestamp!!)
            } else {
                null
            }
        }

    private constructor(
        identityManagerSession: IdentityManagerSession,
        uid: UID,
        contactIdentity: Identity,
        ownedIdentity: Identity,
        serializedDeviceCapabilities: ByteArray?,
        preKey: PreKey?
    ) {
        this.identityManagerSession = identityManagerSession
        this.uid = uid
        this.contactIdentity = contactIdentity
        this.ownedIdentity = ownedIdentity
        this.serializedDeviceCapabilities = serializedDeviceCapabilities
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
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.serializedDeviceCapabilities = res.getBytes(SERIALIZED_DEVICE_CAPABILITIES)
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
            "ContactDevice.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?);"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.setBytes(4, serializedDeviceCapabilities)
            statement.setLong(5, latestChannelCreationPingTimestamp)

            if (preKeyId != null && preKeyEncryptionPublicKey != null && preKeyExpirationTimestamp != null) {
                statement.setBytes(6, preKeyId!!.bytes)
                statement.setBytes(7, Encoded.of(preKeyEncryptionPublicKey!!).bytes)
                statement.setLong(8, preKeyExpirationTimestamp!!)
            } else {
                statement.setBytes(6, null)
                statement.setBytes(7, null)
                statement.setNull(8, Types.BIGINT)
            }
            statement.executeUpdate()
            if (serializedDeviceCapabilities != null) {
                commitHookBits = commitHookBits or HOOK_BIT_CAPABILITIES_UPDATED
            }
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ContactDevice.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            if (serializedDeviceCapabilities != null) {
                commitHookBits = commitHookBits or HOOK_BIT_CAPABILITIES_UPDATED
            }
            commitHookBits = commitHookBits or HOOK_BIT_DEVICE_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }


    // return true if the capabilities did change
    @Throws(SQLException::class)
    fun setRawDeviceCapabilities(rawDeviceCapabilities: Array<String>?): Boolean {
        val serializedDeviceCapabilities =
            ObvCapability.serializeRawDeviceCapabilities(rawDeviceCapabilities)
        if (serializedDeviceCapabilities.contentEquals(this.serializedDeviceCapabilities)) {
            // if the capabilities did not change, do not update/notify
            return false
        }

        identityManagerSession.session.prepareStatement(
            "ContactDevice.setRawDeviceCapabilities",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_DEVICE_CAPABILITIES + " = ? " +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, serializedDeviceCapabilities)
            statement.setBytes(2, this.uid.bytes)
            statement.setBytes(3, this.contactIdentity.getBytes())
            statement.setBytes(4, this.ownedIdentity.getBytes())
            statement.executeUpdate()
            this.serializedDeviceCapabilities = serializedDeviceCapabilities
            commitHookBits = commitHookBits or HOOK_BIT_CAPABILITIES_UPDATED
            identityManagerSession.session.addSessionCommitListener(this)
            return true
        }
    }

    @Throws(SQLException::class)
    fun setLatestChannelCreationPingTimestamp(timestamp: Long) {
        identityManagerSession.session.prepareStatement(
            "ContactDevice.setLatestChannelCreationPingTimestamp",
            "UPDATE " + TABLE_NAME +
                    " SET " + LATEST_CHANNEL_CREATION_PING_TIMESTAMP + " = ? " +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setLong(1, timestamp)
            statement.setBytes(2, this.uid.bytes)
            statement.setBytes(3, this.contactIdentity.getBytes())
            statement.setBytes(4, this.ownedIdentity.getBytes())
            statement.executeUpdate()
            this.latestChannelCreationPingTimestamp = timestamp
        }
    }


    @Throws(SQLException::class)
    fun setPreKey(preKeyBlob: PreKeyBlobOnServer?) {
        identityManagerSession.session.prepareStatement(
            "ContactDevice.setPreKey",
            "UPDATE " + TABLE_NAME +
                    " SET " + PRE_KEY_ID + " = ?, " +
                    PRE_KEY_ENCRYPTION_PUBLIC_KEY + " = ?, " +
                    PRE_KEY_EXPIRATION_TIMESTAMP + " = ? " +
                    " WHERE " + UID_ + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            val preKeyAddedOrRemoved: Boolean
            if (preKeyBlob == null) {
                statement.setNull(1, Types.BLOB)
                statement.setNull(2, Types.BLOB)
                statement.setNull(3, Types.BIGINT)
                preKeyAddedOrRemoved = this.preKeyId != null
                this.preKeyId = null
                this.preKeyEncryptionPublicKey = null
                this.preKeyExpirationTimestamp = null
            } else {
                statement.setBytes(1, preKeyBlob.preKey.keyId!!.bytes)
                statement.setBytes(2, Encoded.of(preKeyBlob.preKey.encryptionPublicKey!!).bytes)
                statement.setLong(3, preKeyBlob.preKey.expirationTimestamp)
                preKeyAddedOrRemoved = this.preKeyId == null
                this.preKeyId = preKeyBlob.preKey.keyId
                this.preKeyEncryptionPublicKey = preKeyBlob.preKey.encryptionPublicKey
                this.preKeyExpirationTimestamp = preKeyBlob.preKey.expirationTimestamp

                if (this.serializedDeviceCapabilities == null && preKeyBlob.rawDeviceCapabilities != null) {
                    setRawDeviceCapabilities(preKeyBlob.rawDeviceCapabilities)
                }
            }
            statement.setBytes(4, uid.bytes)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.executeUpdate()
            if (preKeyAddedOrRemoved) {
                commitHookBits = commitHookBits or HOOK_BIT_DEVICE_CHANGED
                identityManagerSession.session.addSessionCommitListener(this)
            }
        }
    }


    // endregion
    @JvmField var channelCreationAlreadyInProgress: Boolean = false
    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CONTACT_DEVICE_UID_KEY] =
                uid
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CONTACT_IDENTITY_KEY] =
                contactIdentity
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CHANNEL_CREATION_ALREADY_IN_PROGRESS_KEY] =
                channelCreationAlreadyInProgress
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_CAPABILITIES_UPDATED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED_CONTACT_IDENTITY_KEY] =
                contactIdentity
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DEVICE_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED_CONTACT_IDENTITY_KEY] =
                contactIdentity
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED,
                userInfo
            )
        }
        commitHookBits = 0
    }

    companion object {
        const val TABLE_NAME: String = "contact_device"

        const val UID_: String = "uid"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val SERIALIZED_DEVICE_CAPABILITIES: String = "serialized_device_capabilities"
        const val LATEST_CHANNEL_CREATION_PING_TIMESTAMP: String =
            "latest_channel_creation_ping_timestamp"
        const val PRE_KEY_ID: String = "pre_key_id"
        const val PRE_KEY_ENCRYPTION_PUBLIC_KEY: String = "pre_key_encryption_public_key"
        const val PRE_KEY_EXPIRATION_TIMESTAMP: String = "pre_key_expiration_timestamp"


        fun create(
            identityManagerSession: IdentityManagerSession,
            uid: UID?,
            contactIdentity: Identity?,
            ownedIdentity: Identity?,
            preKeyBlob: PreKeyBlobOnServer?,
            channelCreationAlreadyInProgress: Boolean
        ): ContactDevice? {
            if ((uid == null) || (contactIdentity == null) || (ownedIdentity == null)) {
                return null
            }
            try {
                val contactDevice = ContactDevice(
                    identityManagerSession,
                    uid,
                    contactIdentity,
                    ownedIdentity,
                    if (preKeyBlob == null) null else ObvCapability.serializeRawDeviceCapabilities(
                        preKeyBlob.rawDeviceCapabilities
                    ),
                    preKeyBlob?.preKey
                )
                contactDevice.insert()
                contactDevice.channelCreationAlreadyInProgress = channelCreationAlreadyInProgress
                return contactDevice
            } catch (_: SQLException) {
                return null
            }
        }

        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            UID_ + " BLOB NOT NULL, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            SERIALIZED_DEVICE_CAPABILITIES + " BLOB DEFAULT NULL, " +
                            LATEST_CHANNEL_CREATION_PING_TIMESTAMP + " BIGINT NOT NULL DEFAULT 0, " +
                            PRE_KEY_ID + " BLOB DEFAULT NULL, " +
                            PRE_KEY_ENCRYPTION_PUBLIC_KEY + " BLOB DEFAULT NULL, " +
                            PRE_KEY_EXPIRATION_TIMESTAMP + " BIGINT DEFAULT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + UID_ + ", " + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + "), " +
                            "FOREIGN KEY (" + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + ") REFERENCES " + ContactIdentity.TABLE_NAME + " (" + ContactIdentity.CONTACT_IDENTITY + ", " + ContactIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM contact_device AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM contact_identity " +
                                " WHERE identity = p.contact_identity" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
            if (oldVersion < 27 && newVersion >= 27) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_device ADD COLUMN `serialized_device_capabilities` BLOB DEFAULT NULL")
                }
                oldVersion = 27
            }
            if (oldVersion < 41 && newVersion >= 41) {
                Logger.d("MIGRATING `contact_device` DATABASE FROM VERSION " + oldVersion + " TO 41")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_device ADD COLUMN `latest_channel_creation_ping_timestamp` BIGINT NOT NULL DEFAULT 0")
                    statement.execute("ALTER TABLE contact_device ADD COLUMN `pre_key_id` BLOB DEFAULT NULL")
                    statement.execute("ALTER TABLE contact_device ADD COLUMN `pre_key_encryption_public_key` BLOB DEFAULT NULL")
                    statement.execute("ALTER TABLE contact_device ADD COLUMN `pre_key_expiration_timestamp` BIGINT DEFAULT NULL")
                }
                oldVersion = 41
            }
        }

        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            contactDeviceUid: UID,
            contactIdentity: Identity,
            ownedIdentity: Identity
        ): ContactDevice? {
            identityManagerSession.session.prepareStatement(
                "ContactDevice.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " +
                        UID_ + " = ? AND " +
                        CONTACT_IDENTITY + " = ? AND " +
                        OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactDeviceUid.bytes)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    return if (res.next()) {
                        ContactDevice(identityManagerSession, res)
                    } else {
                        null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun exists(
            identityManagerSession: IdentityManagerSession,
            contactDeviceUid: UID,
            contactIdentity: Identity,
            ownedIdentity: Identity
        ): Boolean {
            identityManagerSession.session.prepareStatement(
                "ContactDevice.exists",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + UID_ + " = ? " +
                        " AND " + CONTACT_IDENTITY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactDeviceUid.bytes)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    return res.next()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity,
            ownedIdentity: Identity
        ): Array<ContactDevice?> {
            identityManagerSession.session.prepareStatement(
                "ContactDevice.getAllForContact",
                "SELECT * FROM " + TABLE_NAME + " WHERE " +
                        CONTACT_IDENTITY + " = ? AND " +
                        OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactIdentity.getBytes())
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactDevice?> = ArrayList()
                    while (res.next()) {
                        list.add(ContactDevice(identityManagerSession, res))
                    }
                    return list.toTypedArray<ContactDevice?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(identityManagerSession: IdentityManagerSession): Array<ContactDevice?> {
            identityManagerSession.session.prepareStatement(
                "ContactDevice.getAll",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactDevice?> = ArrayList()
                    while (res.next()) {
                        list.add(ContactDevice(identityManagerSession, res))
                    }
                    return list.toTypedArray<ContactDevice?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithExpiredPreKey(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            expirationTimestamp: Long
        ): MutableList<ContactDevice?> {
            identityManagerSession.session.prepareStatement(
                "ContactDevice.getAllWithExpiredPreKey",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + PRE_KEY_EXPIRATION_TIMESTAMP + " < ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setLong(2, expirationTimestamp)
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactDevice?> = ArrayList()
                    while (res.next()) {
                        list.add(ContactDevice(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        // region setters
        @Throws(SQLException::class)
        fun deleteAll(identityManagerSession: IdentityManagerSession, ownedIdentity: Identity) {
            identityManagerSession.session.prepareStatement(
                "ContactDevice.deleteAll",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        private const val HOOK_BIT_INSERTED: Long = 0x1
        private const val HOOK_BIT_CAPABILITIES_UPDATED: Long = 0x2
        private const val HOOK_BIT_DEVICE_CHANGED: Long = 0x4
    }
}
