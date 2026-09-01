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
import io.olvid.engine.channel.datatypes.NetworkChannel
import io.olvid.engine.channel.datatypes.PreKeyChannel
import io.olvid.engine.channel.datatypes.RatchetingOutput
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AuthEncKeyAndChannelInfo
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.MessageToSend
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.OwnedDeviceAndPreKey
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.UidAndPreKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.ChannelNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.security.InvalidKeyException
import java.sql.ResultSet
import java.sql.SQLException
import java.util.Arrays

class ObliviousChannel : NetworkChannel, ObvDatabase {
    private val channelManagerSession: ChannelManagerSession

    @JvmField val currentDeviceUid: UID
    @JvmField val remoteDeviceUid: UID
    @JvmField val remoteIdentity: Identity
    private var confirmed: Boolean
    private var seedForNextSendKey: Seed
    private var fullRatchetingCountOfLastProvision: Int

    // info used for the full ratcheting
    private var numberOfEncryptedMessages: Int
    private var numberOfEncryptedMessagesAtTheTimeOfTheLastFullRatchet: Int
    private var timestampOfLastFullRatchet: Long
    private var timestampOfLastFullRatchetSentMessage: Long
    private var fullRatchetOfTheSendSeedInProgress: Boolean

    val receptionChannelInfo: ReceptionChannelInfo
        get() = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)

    val numberOfEncryptedMessagesSinceLastFullRatchet: Int
        get() = numberOfEncryptedMessages - numberOfEncryptedMessagesAtTheTimeOfTheLastFullRatchet

    fun requiresFullRatchet(): Boolean {
        if (fullRatchetOfTheSendSeedInProgress) {
            // 1. If too much time passed since the time we sent a message related to the full ratcheting protocol in progress,
            // we decide to start the protocol all over again.
            if (System.currentTimeMillis() - timestampOfLastFullRatchetSentMessage >= Constants.THRESHOLD_TIME_INTERVAL_SINCE_LAST_FULL_RATCHET_SENT_MESSAGE) {
                return true
            }
        } else {
            // 1. If the number of encrypted messages since the last successful full ratchet is too high,
            // we must start a new full ratchet
            if (this.numberOfEncryptedMessagesSinceLastFullRatchet >= Constants.THRESHOLD_NUMBER_OF_ENCRYPTED_MESSAGES_PER_FULL_RATCHET) {
                return true
            }

            // 2. If the elapsed time since the last successful full ratchet is too high,
            // we must start a new full ratchet
            if (System.currentTimeMillis() - timestampOfLastFullRatchet >= Constants.FULL_RATCHET_TIME_INTERVAL_VALIDITY) {
                return true
            }
        }
        return false
    }


    //    public Provision getLatestProvision() {
    //        return Provision.get(channelManagerSession, fullRatchetingCountOfLastProvision, currentDeviceUid, remoteDeviceUid, remoteIdentity);
    //    }
    fun aSendSeedFullRatchetMessageWasSent() {
        try {
            channelManagerSession.session.prepareStatement(
                "ObliviousChannel.aSendSeedFullRatchetMessageWasSent",
                "UPDATE " + TABLE_NAME + " SET " +
                        FULL_RATCHET_OF_THE_SEND_SEED_IN_PROGRESS + " = 1, " +
                        TIMESTAMP_OF_LAST_FULL_RATCHET_SENT_MESSAGE + " = ? " +
                        " WHERE " + CURRENT_DEVICE_UID + " = ? AND " + REMOTE_DEVICE_UID + " = ? AND " + REMOTE_IDENTITY + " = ?;"
            ).use { statement ->
                val now = System.currentTimeMillis()
                statement.setLong(1, now)
                statement.setBytes(2, currentDeviceUid.bytes)
                statement.setBytes(3, remoteDeviceUid.bytes)
                statement.setBytes(4, remoteIdentity.getBytes())
                statement.executeUpdate()
                this.fullRatchetOfTheSendSeedInProgress = true
                this.timestampOfLastFullRatchetSentMessage = now
            }
        } catch (_: SQLException) {
        }
    }

    @Throws(SQLException::class)
    fun confirm() {
        if (confirmed) {
            return
        }
        channelManagerSession.session.prepareStatement(
            "ObliviousChannel.confirm",
            "UPDATE " + TABLE_NAME + " SET " +
                    CONFIRMED + " = 1 " +
                    " WHERE " + CURRENT_DEVICE_UID + " = ? " +
                    " AND " + REMOTE_DEVICE_UID + " = ? " +
                    " AND " + REMOTE_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, currentDeviceUid.bytes)
            statement.setBytes(2, remoteDeviceUid.bytes)
            statement.setBytes(3, remoteIdentity.getBytes())
            statement.executeUpdate()
            this.confirmed = true
            commitHookBits = commitHookBits or HOOK_BIT_CHANNEL_CONFIRMED
            channelManagerSession.session.addSessionCommitListener(this)
        }
    }

    // This method is called after a send full ratchet
    fun updateSendSeed(seed: Seed, obliviousEngineVersion: Int) {
        val sendSeed: Seed = generateDiversifiedSeed(seed, currentDeviceUid, obliviousEngineVersion)
        try {
            channelManagerSession.session.prepareStatement(
                "ObliviousChannel.updateSendSeed",
                "UPDATE " + TABLE_NAME + " SET " +
                        SEED_FOR_NEXT_SEND_KEY + " = ?, " +
                        OBLIVIOUS_ENGINE_VERSION + " = ?, " +
                        NUMBER_OF_ENCRYPTED_MESSAGES_AT_THE_TIME_OF_THE_LAST_FULL_RATCHET + " = ?, " +
                        TIMESTAMP_OF_LAST_FULL_RATCHET + " = ?, " +
                        FULL_RATCHET_OF_THE_SEND_SEED_IN_PROGRESS + " = 0 " +
                        " WHERE " + CURRENT_DEVICE_UID + " = ? AND " + REMOTE_DEVICE_UID + " = ? AND " + REMOTE_IDENTITY + " = ?;"
            ).use { statement ->
                val now = System.currentTimeMillis()
                statement.setBytes(1, sendSeed.getBytes())
                statement.setInt(2, obliviousEngineVersion)
                statement.setInt(3, numberOfEncryptedMessages)
                statement.setLong(4, now)
                statement.setBytes(5, currentDeviceUid.bytes)
                statement.setBytes(6, remoteDeviceUid.bytes)
                statement.setBytes(7, remoteIdentity.getBytes())
                statement.executeUpdate()
                this.seedForNextSendKey = sendSeed
                this.obliviousEngineVersion = obliviousEngineVersion
                this.numberOfEncryptedMessagesAtTheTimeOfTheLastFullRatchet =
                    numberOfEncryptedMessages
                this.timestampOfLastFullRatchet = now
                this.fullRatchetOfTheSendSeedInProgress = false
            }
        } catch (_: SQLException) {
        }
    }

    // This method is called after a receive full ratchet
    @Throws(SQLException::class)
    fun createNewProvision(seed: Seed, obliviousEngineVersion: Int) {
        val receiveSeed: Seed =
            generateDiversifiedSeed(seed, remoteDeviceUid, obliviousEngineVersion)
        val provision: Provision? = Provision.createOrReplace(
            channelManagerSession,
            fullRatchetingCountOfLastProvision + 1,
            this,
            receiveSeed,
            obliviousEngineVersion
        )
        if (provision == null) {
            throw SQLException()
        }
        channelManagerSession.session.prepareStatement(
            "ObliviousChannel.createNewProvision",
            "UPDATE " + TABLE_NAME + " SET " +
                    FULL_RATCHETING_COUNT_OF_LAST_PROVISION + " = ? " +
                    " WHERE " + CURRENT_DEVICE_UID + " = ? AND " + REMOTE_DEVICE_UID + " = ? AND " + REMOTE_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, fullRatchetingCountOfLastProvision + 1)
            statement.setBytes(2, currentDeviceUid.bytes)
            statement.setBytes(3, remoteDeviceUid.bytes)
            statement.setBytes(4, remoteIdentity.getBytes())
            statement.executeUpdate()
            this.fullRatchetingCountOfLastProvision++
        }
    }

    private constructor(
        channelManagerSession: ChannelManagerSession,
        currentDeviceUid: UID,
        remoteDeviceUid: UID,
        remoteIdentity: Identity,
        seedForNextSendKey: Seed,
        obliviousEngineVersion: Int
    ) {
        this.channelManagerSession = channelManagerSession

        this.currentDeviceUid = currentDeviceUid
        this.remoteDeviceUid = remoteDeviceUid
        this.remoteIdentity = remoteIdentity
        this.confirmed = false
        this.obliviousEngineVersion = obliviousEngineVersion

        this.seedForNextSendKey = seedForNextSendKey
        this.fullRatchetingCountOfLastProvision = 0
        this.numberOfEncryptedMessages = 0
        this.numberOfEncryptedMessagesAtTheTimeOfTheLastFullRatchet = 0
        this.timestampOfLastFullRatchet = System.currentTimeMillis()

        this.timestampOfLastFullRatchetSentMessage = this.timestampOfLastFullRatchet
        this.fullRatchetOfTheSendSeedInProgress = false
    }

    private constructor(channelManagerSession: ChannelManagerSession, res: ResultSet) {
        this.channelManagerSession = channelManagerSession

        this.currentDeviceUid = UID(res.getBytes(CURRENT_DEVICE_UID))
        this.remoteDeviceUid = UID(res.getBytes(REMOTE_DEVICE_UID))
        try {
            this.remoteIdentity = Identity.of(res.getBytes(REMOTE_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.confirmed = res.getBoolean(CONFIRMED)
        this.obliviousEngineVersion = res.getInt(OBLIVIOUS_ENGINE_VERSION)

        this.seedForNextSendKey = Seed(res.getBytes(SEED_FOR_NEXT_SEND_KEY))
        this.fullRatchetingCountOfLastProvision =
            res.getInt(FULL_RATCHETING_COUNT_OF_LAST_PROVISION)
        this.numberOfEncryptedMessages = res.getInt(NUMBER_OF_ENCRYPTED_MESSAGES)
        this.numberOfEncryptedMessagesAtTheTimeOfTheLastFullRatchet = res.getInt(
            NUMBER_OF_ENCRYPTED_MESSAGES_AT_THE_TIME_OF_THE_LAST_FULL_RATCHET
        )
        this.timestampOfLastFullRatchet = res.getLong(TIMESTAMP_OF_LAST_FULL_RATCHET)

        this.timestampOfLastFullRatchetSentMessage = res.getLong(
            TIMESTAMP_OF_LAST_FULL_RATCHET_SENT_MESSAGE
        )
        this.fullRatchetOfTheSendSeedInProgress = res.getBoolean(
            FULL_RATCHET_OF_THE_SEND_SEED_IN_PROGRESS
        )
    }


    @Throws(SQLException::class)
    override fun insert() {
        channelManagerSession.session.prepareStatement(
            "ObliviousChannel.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, currentDeviceUid.bytes)
            statement.setBytes(2, remoteDeviceUid.bytes)
            statement.setBytes(3, remoteIdentity.getBytes())
            statement.setBoolean(4, confirmed)
            statement.setInt(5, obliviousEngineVersion)

            statement.setBytes(6, seedForNextSendKey.getBytes())
            statement.setInt(7, fullRatchetingCountOfLastProvision)
            statement.setInt(8, numberOfEncryptedMessages)
            statement.setInt(9, numberOfEncryptedMessagesAtTheTimeOfTheLastFullRatchet)
            statement.setLong(10, timestampOfLastFullRatchet)

            statement.setLong(11, timestampOfLastFullRatchetSentMessage)
            statement.setBoolean(12, fullRatchetOfTheSendSeedInProgress)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        channelManagerSession.session.prepareStatement(
            "ObliviousChannel.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + CURRENT_DEVICE_UID + " = ? AND " + REMOTE_DEVICE_UID + " = ? AND " + REMOTE_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, currentDeviceUid.bytes)
            statement.setBytes(2, remoteDeviceUid.bytes)
            statement.setBytes(3, remoteIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_CHANNEL_DELETED
            channelManagerSession.session.addSessionCommitListener(this)
        }
    }


    // endregion
    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_NEED_FULL_RATCHET) != 0L) {
            if (channelManagerSession.fullRatchetProtocolStarterDelegate != null) {
                try {
                    channelManagerSession.fullRatchetProtocolStarterDelegate.startFullRatchetProtocolForObliviousChannel(
                        currentDeviceUid,
                        remoteDeviceUid,
                        remoteIdentity
                    )
                } catch (e: Exception) {
                    // no need to do anything, the next message will try to restart the full ratchet
                    Logger.x(e)
                }
            } else {
                Logger.w("Full ratchet required, but no FullRatchetProtocolStarterDelegate is set.")
            }
        }
        if ((commitHookBits and HOOK_BIT_CHANNEL_CONFIRMED) != 0L) {
            // refresh members of groups owned by the remoteIdentity (useful after a backup restore)
            channelManagerSession.identityDelegate!!.refreshMembersOfGroupsOwnedByGroupOwner(
                currentDeviceUid,
                remoteIdentity
            )
            // re-invite members of groups owned (useful after a backup restore)
            channelManagerSession.identityDelegate.pushMembersOfOwnedGroupsToContact(
                currentDeviceUid,
                remoteIdentity
            )
            // resend a batch of all keys for common groups V2
            channelManagerSession.identityDelegate.initiateGroupV2BatchKeysResend(
                currentDeviceUid,
                remoteIdentity,
                remoteDeviceUid
            )

            val userInfo = HashMap<String, Any>()
            userInfo[ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_CURRENT_DEVICE_UID_KEY] =
                currentDeviceUid
            userInfo[ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_REMOTE_IDENTITY_KEY] =
                remoteIdentity
            userInfo[ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_REMOTE_DEVICE_UID__KEY] =
                remoteDeviceUid
            channelManagerSession.notificationPostingDelegate?.postNotification(
                ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_CHANNEL_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_CURRENT_DEVICE_UID_KEY] =
                currentDeviceUid
            userInfo[ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_REMOTE_IDENTITY_KEY] =
                remoteIdentity
            channelManagerSession.notificationPostingDelegate?.postNotification(
                ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED,
                userInfo
            )
        }
        commitHookBits = 0
    }


    override fun wrapMessageKey(
        messageKey: AuthEncKey?,
        prng: PRNGService?,
        partOfFullRatchetProtocol: Boolean
    ): MessageToSend.Header? {
        val protocolMessage = partOfFullRatchetProtocol
        val ratchetingOutput: RatchetingOutput? =
            computeSelfRatchet(seedForNextSendKey, obliviousEngineVersion)
        if (ratchetingOutput == null) {
            return null
        }
        val authEnc = Suite.getAuthEnc(ratchetingOutput.authEncKey)
        val encryptedMessageKey: EncryptedBytes

        try {
            encryptedMessageKey = authEnc!!.encrypt(
                ratchetingOutput.authEncKey,
                Encoded.of(messageKey!!).bytes,
                prng
            )
        } catch (e: InvalidKeyException) {
            Logger.x(e)
            return null
        }
        val headerBytes = ByteArray(KeyId.KEYID_LENGTH + encryptedMessageKey.length)
        System.arraycopy(ratchetingOutput.keyId!!.bytes, 0, headerBytes, 0, KeyId.KEYID_LENGTH)
        System.arraycopy(
            encryptedMessageKey.getBytes(),
            0,
            headerBytes,
            KeyId.KEYID_LENGTH,
            encryptedMessageKey.length
        )

        val header =
            MessageToSend.Header(remoteDeviceUid, remoteIdentity, EncryptedBytes(headerBytes))
        try {
            channelManagerSession.session.prepareStatement(
                "ObliviousChannel.wrapMessageKey",
                "UPDATE " + TABLE_NAME + " SET " +
                        SEED_FOR_NEXT_SEND_KEY + " = ?, " +
                        NUMBER_OF_ENCRYPTED_MESSAGES + " = ? " +
                        " WHERE " + CURRENT_DEVICE_UID + " = ? AND " + REMOTE_DEVICE_UID + " = ? AND " + REMOTE_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ratchetingOutput.ratchetedSeed!!.getBytes())
                statement.setInt(2, numberOfEncryptedMessages + 1)
                statement.setBytes(3, currentDeviceUid.bytes)
                statement.setBytes(4, remoteDeviceUid.bytes)
                statement.setBytes(5, remoteIdentity.getBytes())
                statement.executeUpdate()
                this.seedForNextSendKey = ratchetingOutput.ratchetedSeed
                this.numberOfEncryptedMessages++
                if (!protocolMessage && requiresFullRatchet()) {
                    aSendSeedFullRatchetMessageWasSent()

                    commitHookBits = commitHookBits or HOOK_BIT_NEED_FULL_RATCHET
                    channelManagerSession.session.addSessionCommitListener(this)
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            return null
        }
        return header
    }

    companion object {
        const val TABLE_NAME: String = "oblivious_channel"

        const val CURRENT_DEVICE_UID: String = "current_device_uid"
        const val REMOTE_DEVICE_UID: String = "remote_device_uid"
        const val REMOTE_IDENTITY: String = "contact_identity"
        const val CONFIRMED: String = "confirmed"

        // there is already a obliviousEngineVersion field in the Channal parent class for this DB field
        // private int obliviousEngineVersion;
        const val OBLIVIOUS_ENGINE_VERSION: String = "oblivious_engine_version"
        const val SEED_FOR_NEXT_SEND_KEY: String = "seed_for_next_send_key"
        const val FULL_RATCHETING_COUNT_OF_LAST_PROVISION: String =
            "full_ratcheting_count_of_last_provision"

        const val NUMBER_OF_ENCRYPTED_MESSAGES: String = "number_of_encrypted_messages"
        const val NUMBER_OF_ENCRYPTED_MESSAGES_AT_THE_TIME_OF_THE_LAST_FULL_RATCHET: String =
            "number_of_encrypted_messages_at_the_time_of_the_last_full_ratchet"
        const val TIMESTAMP_OF_LAST_FULL_RATCHET: String = "timestamp_of_last_full_ratchet"
        const val TIMESTAMP_OF_LAST_FULL_RATCHET_SENT_MESSAGE: String =
            "timestamp_of_last_full_ratchet_sent_message"
        const val FULL_RATCHET_OF_THE_SEND_SEED_IN_PROGRESS: String =
            "full_ratchet_of_the_send_seed_in_progress"


        fun clean(channelManagerSession: ChannelManagerSession) {
            ProvisionedKeyMaterial.deleteAllExpired(channelManagerSession)
            Provision.deleteAllEmpty(channelManagerSession)
        }

        fun create(
            channelManagerSession: ChannelManagerSession,
            currentDeviceUid: UID?,
            remoteDeviceUid: UID?,
            remoteIdentity: Identity?,
            seed: Seed?,
            obliviousEngineVersion: Int
        ): ObliviousChannel? {
            if ((currentDeviceUid == null) || (remoteDeviceUid == null) || (remoteIdentity == null) || (seed == null)) {
                return null
            }
            val sendSeed: Seed =
                generateDiversifiedSeed(seed, currentDeviceUid, obliviousEngineVersion)
            val receiveSeed: Seed =
                generateDiversifiedSeed(seed, remoteDeviceUid, obliviousEngineVersion)
            try {
                val obliviousChannel = ObliviousChannel(
                    channelManagerSession,
                    currentDeviceUid,
                    remoteDeviceUid,
                    remoteIdentity,
                    sendSeed,
                    obliviousEngineVersion
                )
                obliviousChannel.insert()
                val provision: Provision? = Provision.createOrReplace(
                    channelManagerSession,
                    0,
                    obliviousChannel,
                    receiveSeed,
                    obliviousEngineVersion
                )
                if (provision == null) {
                    obliviousChannel.delete()
                    throw SQLException()
                }
                return obliviousChannel
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
                            CURRENT_DEVICE_UID + " BLOB NOT NULL, " +
                            REMOTE_DEVICE_UID + " BLOB NOT NULL, " +
                            REMOTE_IDENTITY + " BLOB NOT NULL, " +
                            CONFIRMED + " BIT NOT NULL, " +
                            OBLIVIOUS_ENGINE_VERSION + " INT NOT NULL, " +
                            SEED_FOR_NEXT_SEND_KEY + " BLOB NOT NULL, " +
                            FULL_RATCHETING_COUNT_OF_LAST_PROVISION + " INT NOT NULL, " +
                            NUMBER_OF_ENCRYPTED_MESSAGES + " INT NOT NULL, " +
                            NUMBER_OF_ENCRYPTED_MESSAGES_AT_THE_TIME_OF_THE_LAST_FULL_RATCHET + " INT NOT NULL, " +
                            TIMESTAMP_OF_LAST_FULL_RATCHET + " BIGINT NOT NULL, " +
                            TIMESTAMP_OF_LAST_FULL_RATCHET_SENT_MESSAGE + " BIGINT NOT NULL, " +
                            FULL_RATCHET_OF_THE_SEND_SEED_IN_PROGRESS + " BIT NOT NULL, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + CURRENT_DEVICE_UID + ", " + REMOTE_DEVICE_UID + ", " + REMOTE_IDENTITY + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 39 && newVersion >= 39) {
                Logger.d("MIGRATING `oblivious_channel` DATABASE FROM VERSION " + oldVersion + " TO 39")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE oblivious_channel ADD COLUMN `supports_gkmv_2` BIT NOT NULL DEFAULT 0")
                    statement.execute("ALTER TABLE oblivious_channel ADD COLUMN `full_ratcheting_count_with_gkmv_2_support` INT NOT NULL DEFAULT -1")
                    statement.execute("ALTER TABLE oblivious_channel ADD COLUMN `self_ratcheting_count_with_gkmv_2_support` INT NOT NULL DEFAULT -1")
                }
                oldVersion = 39
            }
            if (oldVersion < 46 && newVersion >= 46) {
                Logger.d("MIGRATING `oblivious_channel` DATABASE FROM VERSION " + oldVersion + " TO 46")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE oblivious_channel DROP COLUMN `number_of_encrypted_messages_since_last_full_ratchet_sent_message`")
                    statement.execute("ALTER TABLE oblivious_channel DROP COLUMN `number_of_decrypted_messages_since_last_full_ratchet_sent_message`")
                }
                oldVersion = 46
            }
            if (oldVersion < 47 && newVersion >= 47) {
                Logger.d("MIGRATING `oblivious_channel` DATABASE FROM VERSION " + oldVersion + " TO 47")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE oblivious_channel DROP COLUMN `supports_gkmv_2`")
                    statement.execute("ALTER TABLE oblivious_channel DROP COLUMN `full_ratcheting_count_with_gkmv_2_support`")
                    statement.execute("ALTER TABLE oblivious_channel DROP COLUMN `self_ratcheting_count_with_gkmv_2_support`")
                }
                oldVersion = 47
            }
        }

        // region getters
        fun get(
            channelManagerSession: ChannelManagerSession,
            currentDeviceUid: UID?,
            remoteDeviceUid: UID?,
            remoteIdentity: Identity?,
            necessarilyConfirmed: Boolean
        ): ObliviousChannel? {
            if ((currentDeviceUid == null) || (remoteDeviceUid == null) || (remoteIdentity == null)) {
                return null
            }
            try {
                channelManagerSession.session.prepareStatement(
                    "ObliviousChannel.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " +
                            (if (necessarilyConfirmed) (CONFIRMED + " = 1 AND ") else "") +
                            CURRENT_DEVICE_UID + " = ? AND " + REMOTE_DEVICE_UID + " = ? AND " + REMOTE_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, currentDeviceUid.bytes)
                    statement.setBytes(2, remoteDeviceUid.bytes)
                    statement.setBytes(3, remoteIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return ObliviousChannel(channelManagerSession, res)
                        }
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
            }
            return null
        }

        fun getAll(channelManagerSession: ChannelManagerSession): Array<ObliviousChannel?> {
            try {
                channelManagerSession.session.prepareStatement(
                    "ObliviousChannel.getAll",
                    "SELECT * FROM " + TABLE_NAME
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<ObliviousChannel?> = ArrayList<ObliviousChannel?>()
                        while (res.next()) {
                            list.add(ObliviousChannel(channelManagerSession, res))
                        }
                        return list.toTypedArray<ObliviousChannel?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<ObliviousChannel>(0)
            }
        }


        //    public static ObliviousChannel[] getAllConfirmed(ChannelManagerSession channelManagerSession) {
        //        try (PreparedStatement statement = channelManagerSession.session.prepareStatement("SELECT * FROM " + TABLE_NAME +
        //                " WHERE " + CONFIRMED + " = 1;")) {
        //            try (ResultSet res = statement.executeQuery()) {
        //                List<ObliviousChannel> list = new ArrayList<>();
        //                while (res.next()) {
        //                    list.add(new ObliviousChannel(channelManagerSession, res));
        //                }
        //                return list.toArray(new ObliviousChannel[0]);
        //            }
        //        } catch (SQLException e) {
        //            return new ObliviousChannel[0];
        //        }
        //    }
        fun getMany(
            channelManagerSession: ChannelManagerSession,
            currentDeviceUid: UID?,
            remoteDeviceUids: Array<UID?>?,
            remoteIdentity: Identity?,
            necessarilyConfirmed: Boolean
        ): Array<ObliviousChannel>? {
            if ((currentDeviceUid == null) || (remoteDeviceUids == null) || (remoteDeviceUids.size == 0) || (remoteIdentity == null)) {
                return null
            }
            var questionMarks = "("
            for (i in remoteDeviceUids.indices) {
                if (i == 0) {
                    questionMarks += "?"
                } else {
                    questionMarks += ",?"
                }
            }
            questionMarks += ")"
            try {
                channelManagerSession.session.prepareStatement(
                    "ObliviousChannel.getMany",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " +
                            (if (necessarilyConfirmed) (CONFIRMED + " = 1 AND ") else "") +
                            CURRENT_DEVICE_UID + " = ? AND " +
                            REMOTE_IDENTITY + " = ? AND " +
                            REMOTE_DEVICE_UID + " IN " + questionMarks + ";"
                ).use { statement ->
                    statement.setBytes(1, currentDeviceUid.bytes)
                    statement.setBytes(2, remoteIdentity.getBytes())
                    for (i in remoteDeviceUids.indices) {
                        statement.setBytes(3 + i, remoteDeviceUids[i]!!.bytes)
                    }
                    statement.executeQuery().use { res ->
                        val list: MutableList<ObliviousChannel> = ArrayList<ObliviousChannel>()
                        while (res.next()) {
                            list.add(ObliviousChannel(channelManagerSession, res))
                        }
                        return list.toTypedArray<ObliviousChannel>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOf<ObliviousChannel>()
            }
        }

        fun deleteMany(
            channelManagerSession: ChannelManagerSession,
            currentDeviceUid: UID?,
            remoteDeviceUids: Array<UID?>?,
            remoteIdentity: Identity?
        ) {
            if ((currentDeviceUid == null) || (remoteDeviceUids == null) || (remoteDeviceUids.size == 0) || (remoteIdentity == null)) {
                return
            }
            var questionMarks = "("
            for (i in remoteDeviceUids.indices) {
                if (i == 0) {
                    questionMarks += "?"
                } else {
                    questionMarks += ",?"
                }
            }
            questionMarks += ")"
            try {
                channelManagerSession.session.prepareStatement(
                    "ObliviousChannel.deleteMany",
                    "DELETE FROM " + TABLE_NAME + " WHERE " +
                            CURRENT_DEVICE_UID + " = ? AND " +
                            REMOTE_IDENTITY + " = ? AND " +
                            REMOTE_DEVICE_UID + " IN " + questionMarks + ";"
                ).use { statement ->
                    statement.setBytes(1, currentDeviceUid.bytes)
                    statement.setBytes(2, remoteIdentity.getBytes())
                    for (i in remoteDeviceUids.indices) {
                        statement.setBytes(3 + i, remoteDeviceUids[i]!!.bytes)
                    }
                    statement.executeUpdate()
                    channelManagerSession.session.addSessionCommitListener(SessionCommitListener {
                        val userInfo = HashMap<String, Any>()
                        userInfo.put(
                            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_CURRENT_DEVICE_UID_KEY,
                            currentDeviceUid
                        )
                        userInfo.put(
                            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_REMOTE_IDENTITY_KEY,
                            remoteIdentity
                        )
                        channelManagerSession.notificationPostingDelegate?.postNotification(
                            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED,
                            userInfo
                        )
                    })
                }
            } catch (e: SQLException) {
                Logger.x(e)
            }
        }

        @Throws(SQLException::class)
        fun deleteAll(channelManagerSession: ChannelManagerSession, currentDeviceUid: UID?) {
            if (currentDeviceUid == null) {
                return
            }
            channelManagerSession.session.prepareStatement(
                "ObliviousChannel.deleteAll",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + CURRENT_DEVICE_UID + " = ?;"
            ).use { statement ->
                statement.setBytes(1, currentDeviceUid.bytes)
                statement.executeQuery().use { res ->
                    while (res.next()) {
                        try {
                            val obliviousChannel = ObliviousChannel(channelManagerSession, res)
                            obliviousChannel.delete()
                        } catch (_: SQLException) { }
                    }
                }
            }
        }


        private const val HOOK_BIT_NEED_FULL_RATCHET: Long = 0x1
        private const val HOOK_BIT_CHANNEL_CONFIRMED: Long = 0x2
        private const val HOOK_BIT_CHANNEL_DELETED: Long = 0x4

        fun computeSelfRatchet(seed: Seed?, obliviousEngineVersion: Int): RatchetingOutput? {
            val prng = Suite.getDefaultPRNG(obliviousEngineVersion, seed ?: return null)

            val ratchetedSeed = Seed(prng)
            val keyId = KeyId(prng.bytes(KeyId.KEYID_LENGTH))
            val authEncKey: AuthEncKey?

            val kdf = Suite.getDefaultKDF(obliviousEngineVersion)
            val kdfSeed = Seed(prng)
            try {
                authEncKey = kdf.gen(
                    kdfSeed,
                    Suite.getDefaultAuthEnc(obliviousEngineVersion).getKDFDelegate()
                )[0] as? AuthEncKey
            } catch (_: Exception) {
                return null
            }
            return RatchetingOutput(ratchetedSeed, keyId, authEncKey)
        }

        private fun generateDiversifiedSeed(
            seed: Seed,
            uid: UID,
            obliviousEngineVersion: Int
        ): Seed {
            val longSeedBytes = ByteArray(seed.length + uid.bytes.size)
            System.arraycopy(seed.getBytes(), 0, longSeedBytes, 0, seed.length)
            System.arraycopy(uid.bytes, 0, longSeedBytes, seed.length, uid.bytes.size)
            val prng = Suite.getDefaultPRNG(obliviousEngineVersion, Seed(longSeedBytes))
            return Seed(prng)
        }


        @Throws(SQLException::class)
        fun acceptableChannelsForPosting(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend
        ): Array<NetworkChannel?> {
            if (channelManagerSession.identityDelegate == null) {
                Logger.w("Calling acceptableChannelsForPosting with no IdentityDelegate set.")
                return arrayOfNulls<NetworkChannel>(0)
            }

            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.OBLIVIOUS_CHANNEL_TYPE -> {
                    if (!message.sendChannelInfo!!.getNecessarilyConfirmed()!! && message.messageType != MessageType.PROTOCOL_MESSAGE_TYPE) {
                        // Only protocol messages may be sent through unconfirmed channels
                        return arrayOfNulls<NetworkChannel>(0)
                    }
                    val remoteDeviceUidSet: HashSet<UID?>?
                    if (message.sendChannelInfo!!.getFromIdentity() == message.sendChannelInfo!!.getToIdentity()) {
                        // posting for owned identity
                        remoteDeviceUidSet = HashSet<UID?>(
                            Arrays.asList<UID?>(
                                *channelManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                                    channelManagerSession.session,
                                    message.sendChannelInfo!!.getFromIdentity()
                                )!!
                            )
                        )
                    } else {
                        // posting for contact
                        remoteDeviceUidSet = HashSet<UID?>(
                            Arrays.asList<UID?>(
                                *channelManagerSession.identityDelegate.getDeviceUidsOfContactIdentity(
                                    channelManagerSession.session,
                                    message.sendChannelInfo!!.getFromIdentity(),
                                    message.sendChannelInfo!!.getToIdentity()
                                )!!
                            )
                        )
                    }
                    remoteDeviceUidSet.retainAll(Arrays.asList<UID?>(*message.sendChannelInfo!!.getRemoteDeviceUids()!!))
                    val currentDeviceUid =
                        channelManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getFromIdentity()
                        )

                    return Companion.getAcceptableObliviousChannels(
                        channelManagerSession,
                        currentDeviceUid,
                        remoteDeviceUidSet.toTypedArray<UID?>(),
                        message.sendChannelInfo!!.getToIdentity(),
                        message.sendChannelInfo!!.getNecessarilyConfirmed()!!
                    ).toTypedArray<NetworkChannel?>()
                }

                SendChannelInfo.ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE -> {
                    val acceptableChannels: MutableList<NetworkChannel?> =
                        ArrayList<NetworkChannel?>()
                    val currentDeviceUid =
                        channelManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getFromIdentity()
                        )
                    var i = 0
                    while (i < message.sendChannelInfo!!.getToIdentities()!!.size) {
                        val toIdentity = message.sendChannelInfo!!.getToIdentities()!![i]
                        val toDeviceUid = message.sendChannelInfo!!.getRemoteDeviceUids()!![i]
                        var uidsAndPreKeys: MutableList<UidAndPreKey?> = ArrayList<UidAndPreKey?>()
                        if (message.sendChannelInfo!!.getFromIdentity() == toIdentity) {
                            val ownedDeviceAndPreKeys: MutableList<OwnedDeviceAndPreKey?>? =
                                channelManagerSession.identityDelegate.getDevicesAndPreKeysOfOwnedIdentity(
                                    channelManagerSession.session,
                                    message.sendChannelInfo!!.getFromIdentity()
                                )
                            for (ownedDeviceAndPreKey in ownedDeviceAndPreKeys!!) {
                                if (ownedDeviceAndPreKey != null && !ownedDeviceAndPreKey.currentDevice) {
                                    uidsAndPreKeys.add(
                                        UidAndPreKey(
                                            ownedDeviceAndPreKey.deviceUid,
                                            ownedDeviceAndPreKey.preKey
                                        )
                                    )
                                }
                            }
                        } else {
                            uidsAndPreKeys =
                                channelManagerSession.identityDelegate.getDeviceUidsAndPreKeysOfContactIdentity(
                                    channelManagerSession.session,
                                    message.sendChannelInfo!!.getFromIdentity(),
                                    toIdentity
                                ) ?: ArrayList<UidAndPreKey?>()
                        }
                        // if a toDeviceUid is specified, only send to it. If not found, still send to all devices
                        if (toDeviceUid != null) {
                            var uidAndPreKeyFound: UidAndPreKey? = null
                            for (uidAndPreKey in uidsAndPreKeys) {
                                if (uidAndPreKey?.uid?.equals(toDeviceUid) == true) {
                                    uidAndPreKeyFound = uidAndPreKey
                                    break
                                }
                            }
                            if (uidAndPreKeyFound != null) {
                                acceptableChannels.addAll(
                                    getAcceptableObliviousOrPreKeyChannels(
                                        channelManagerSession,
                                        message.sendChannelInfo!!.getFromIdentity(),
                                        currentDeviceUid,
                                        arrayOf<UidAndPreKey?>(uidAndPreKeyFound),
                                        toIdentity
                                    )
                                )
                                i++
                                continue
                            }
                        }
                        acceptableChannels.addAll(
                            Companion.getAcceptableObliviousOrPreKeyChannels(
                                channelManagerSession,
                                message.sendChannelInfo!!.getFromIdentity(),
                                currentDeviceUid,
                                uidsAndPreKeys.toTypedArray<UidAndPreKey?>(),
                                toIdentity
                            )
                        )
                        i++
                    }
                    return acceptableChannels.toTypedArray<NetworkChannel?>()
                }

                SendChannelInfo.ALL_OWNED_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_TYPE -> {
                    val uidsAndPreKeys: MutableList<UidAndPreKey?> = ArrayList<UidAndPreKey?>()
                    val ownedDeviceAndPreKeys: MutableList<OwnedDeviceAndPreKey?>? =
                        channelManagerSession.identityDelegate.getDevicesAndPreKeysOfOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getFromIdentity()
                        )
                    for (ownedDeviceAndPreKey in ownedDeviceAndPreKeys!!) {
                        if (ownedDeviceAndPreKey != null && !ownedDeviceAndPreKey.currentDevice) {
                            uidsAndPreKeys.add(
                                UidAndPreKey(
                                    ownedDeviceAndPreKey.deviceUid,
                                    ownedDeviceAndPreKey.preKey
                                )
                            )
                        }
                    }

                    val currentDeviceUid =
                        channelManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getFromIdentity()
                        )
                    return Companion.getAcceptableObliviousOrPreKeyChannels(
                        channelManagerSession,
                        message.sendChannelInfo!!.getFromIdentity(),
                        currentDeviceUid,
                        uidsAndPreKeys.toTypedArray<UidAndPreKey?>(),
                        message.sendChannelInfo!!.getToIdentity()
                    ).toTypedArray<NetworkChannel?>()
                }

                SendChannelInfo.OBLIVIOUS_CHANNEL_OR_PRE_KEY_TYPE -> {
                    var uidsAndPreKeys: MutableList<UidAndPreKey?> = ArrayList<UidAndPreKey?>()
                    if (message.sendChannelInfo!!.getFromIdentity() == message.sendChannelInfo!!.getToIdentity()) {
                        val ownedDeviceAndPreKeys: MutableList<OwnedDeviceAndPreKey?>? =
                            channelManagerSession.identityDelegate.getDevicesAndPreKeysOfOwnedIdentity(
                                channelManagerSession.session,
                                message.sendChannelInfo!!.getFromIdentity()
                            )
                        for (ownedDeviceAndPreKey in ownedDeviceAndPreKeys!!) {
                            if (ownedDeviceAndPreKey != null && !ownedDeviceAndPreKey.currentDevice) {
                                uidsAndPreKeys.add(
                                    UidAndPreKey(
                                        ownedDeviceAndPreKey.deviceUid,
                                        ownedDeviceAndPreKey.preKey
                                    )
                                )
                            }
                        }
                    } else {
                        uidsAndPreKeys =
                            channelManagerSession.identityDelegate.getDeviceUidsAndPreKeysOfContactIdentity(
                                channelManagerSession.session,
                                message.sendChannelInfo!!.getFromIdentity(),
                                message.sendChannelInfo!!.getToIdentity()
                            ) ?: ArrayList<UidAndPreKey?>()
                    }

                    val remoteUids =
                        HashSet<UID?>(Arrays.asList<UID?>(*message.sendChannelInfo!!.getRemoteDeviceUids()!!))
                    val remoteUidsAndPreKeys: MutableList<UidAndPreKey?> =
                        ArrayList<UidAndPreKey?>()
                    for (uidAndPreKey in uidsAndPreKeys) {
                        if (remoteUids.contains(uidAndPreKey?.uid)) {
                            remoteUidsAndPreKeys.add(uidAndPreKey)
                        }
                    }

                    val currentDeviceUid =
                        channelManagerSession.identityDelegate.getCurrentDeviceUidOfOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getFromIdentity()
                        )
                    return Companion.getAcceptableObliviousOrPreKeyChannels(
                        channelManagerSession,
                        message.sendChannelInfo!!.getFromIdentity(),
                        currentDeviceUid,
                        remoteUidsAndPreKeys.toTypedArray<UidAndPreKey?>(),
                        message.sendChannelInfo!!.getToIdentity()
                    ).toTypedArray<NetworkChannel?>()
                }

                else -> return arrayOfNulls<NetworkChannel>(0)
            }
        }

        private fun getAcceptableObliviousOrPreKeyChannels(
            channelManagerSession: ChannelManagerSession,
            ownedIdentity: Identity?,
            currentDeviceUid: UID?,
            remoteDeviceUidsAndPreKeys: Array<UidAndPreKey?>,
            remoteIdentity: Identity?
        ): MutableList<NetworkChannel> {
            // first get all oblivious channels
            val uids = arrayOfNulls<UID>(remoteDeviceUidsAndPreKeys.size)
            for (i in remoteDeviceUidsAndPreKeys.indices) {
                uids[i] = remoteDeviceUidsAndPreKeys[i]?.uid
            }
            val obliviousChannels: MutableList<ObliviousChannel> = getAcceptableObliviousChannels(
                channelManagerSession,
                currentDeviceUid,
                uids,
                remoteIdentity,
                true
            )
            val obliviousChannelUids = HashSet<UID?>()
            for (obliviousChannel in obliviousChannels) {
                obliviousChannelUids.add(obliviousChannel.remoteDeviceUid)
            }

            val acceptableChannels: MutableList<NetworkChannel> = ArrayList<NetworkChannel>()
            for (uidAndPreKey in remoteDeviceUidsAndPreKeys) {
                if (uidAndPreKey != null && !obliviousChannelUids.contains(uidAndPreKey.uid) && uidAndPreKey.preKey != null) {
                    acceptableChannels.add(
                        PreKeyChannel(
                            channelManagerSession.session,
                            ownedIdentity,
                            remoteIdentity,
                            uidAndPreKey.uid,
                            channelManagerSession.preKeyEncryptionDelegate
                        )
                    )
                }
            }

            acceptableChannels.addAll(obliviousChannels)
            return acceptableChannels
        }

        private fun getAcceptableObliviousChannels(
            channelManagerSession: ChannelManagerSession,
            currentDeviceUid: UID?,
            remoteDeviceUids: Array<UID?>?,
            remoteIdentity: Identity?,
            necessarilyConfirmed: Boolean
        ): MutableList<ObliviousChannel> {
            val channels: Array<ObliviousChannel>? = getMany(
                channelManagerSession,
                currentDeviceUid,
                remoteDeviceUids,
                remoteIdentity,
                necessarilyConfirmed
            )
            if (channels == null) {
                return mutableListOf<ObliviousChannel>()
            }
            val channelList: MutableList<ObliviousChannel> = ArrayList<ObliviousChannel>()
            for (channel in channels) {
                if (channel.obliviousEngineVersion >= Suite.MINIMUM_ACCEPTABLE_VERSION) {
                    channelList.add(channel)
                }
            }
            return channelList
        }

        fun unwrapMessageKey(
            channelManagerSession: ChannelManagerSession,
            header: NetworkReceivedMessage.Header
        ): AuthEncKeyAndChannelInfo? {
            val bytes = header.getWrappedKey()!!.getBytes()
            if (bytes.size < KeyId.KEYID_LENGTH) {
                return null
            }
            val keyId = KeyId(Arrays.copyOfRange(bytes, 0, KeyId.KEYID_LENGTH))
            val encryptedMessageKey =
                EncryptedBytes(Arrays.copyOfRange(bytes, KeyId.KEYID_LENGTH, bytes.size))
            val deviceUid: UID?
            try {
                deviceUid =
                    channelManagerSession.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(
                        channelManagerSession.session,
                        header.getOwnedIdentity()
                    )
            } catch (e: SQLException) {
                Logger.e("Error retrieving a currentDeviceUid -> a received message might have been lost...")
                Logger.x(e)
                return null
            }
            val provisionedKeys: Array<ProvisionedKeyMaterial?> =
                ProvisionedKeyMaterial.getAll(channelManagerSession, keyId, deviceUid)
            for (provisionedKey in provisionedKeys) {
                if (provisionedKey == null) continue
                try {
                    val authEnc = Suite.getAuthEnc(provisionedKey.authEncKey)
                    val encodedMessageKey = Encoded(
                        authEnc!!.decrypt(
                            provisionedKey.authEncKey,
                            encryptedMessageKey
                        )!!
                    )
                    val messageKey = encodedMessageKey.decodeSymmetricKey() as AuthEncKey?
                    val obliviousChannel = provisionedKey.obliviousChannel
                    if (obliviousChannel == null) {
                        Logger.w("While unwrapping a message key, a provision was found without a corresponding channel.")
                        continue
                    }

                    /**///////////// */
                    // From this point, we start modifying the database and must not return null
                    /**///////////// */
                    provisionedKey.setExpirationTimestampsOfOlderProvisionedKeyMaterials()

                    run {
                        val provision: Provision? = Provision.get(
                            channelManagerSession,
                            provisionedKey.provisionFullRatchetingCount,
                            provisionedKey.provisionObliviousChannelCurrentDeviceUid,
                            provisionedKey.provisionObliviousChannelRemoteDeviceUid,
                            provisionedKey.provisionObliviousChannelRemoteIdentity
                        )
                        if (provision != null) {
                            provision.selfRatchetIfRequired()
                        }
                    }

                    try {
                        provisionedKey.delete()
                        if (!obliviousChannel.confirmed) {
                            obliviousChannel.confirm()
                        }
                    } catch (e: SQLException) {
                        Logger.x(e)
                    }
                    return AuthEncKeyAndChannelInfo(
                        messageKey,
                        obliviousChannel.receptionChannelInfo
                    )
                } catch (_: InvalidKeyException) {
                } catch (_: DecryptionException) {
                } catch (_: DecodingException) {
                } catch (_: ClassCastException) {
                }
            }
            return null
        }
    }
}
