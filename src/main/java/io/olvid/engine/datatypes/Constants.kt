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
package io.olvid.engine.datatypes

import java.nio.charset.StandardCharsets


object Constants {
    const val CURRENT_ENGINE_DB_SCHEMA_VERSION: Int = 52
    const val SERVER_API_VERSION: Int = 21
    const val CURRENT_BACKUP_JSON_VERSION: Int = 0

    // files / folders
    const val ENGINE_DB_FILENAME: String = "engine_db.sqlite"
    const val TMP_ENGINE_ENCRYPTED_DB_FILENAME: String = "engine_encrypted_db.sqlite"
    const val INBOUND_ATTACHMENTS_DIRECTORY: String = "inbound_attachments"
    const val IDENTITY_PHOTOS_DIRECTORY: String = "identity_photos"
    const val DOWNLOADED_USER_DATA_DIRECTORY: String = "downloaded_user_data"


    // API key statuses
    const val API_KEY_STATUS_VALID: Int = 0
    const val API_KEY_STATUS_UNKNOWN: Int = 1
    const val API_KEY_STATUS_LICENSES_EXHAUSTED: Int = 2
    const val API_KEY_STATUS_EXPIRED: Int = 3
    const val API_KEY_STATUS_OPEN_BETA_KEY: Int = 4
    const val API_KEY_STATUS_FREE_TRIAL_KEY: Int = 5
    const val API_KEY_STATUS_AWAITING_PAYMENT_GRACE_PERIOD: Int = 6
    const val API_KEY_STATUS_AWAITING_PAYMENT_ON_HOLD: Int = 7
    const val API_KEY_STATUS_FREE_TRIAL_KEY_EXPIRED: Int = 8

    // API key permission code (bits of a single permissions long)
    val API_KEY_PERMISSION_CALL: Long = 1L shl 0
    val API_KEY_PERMISSION_WEB_CLIENT: Long = 1L shl 1
    val API_KEY_PERMISSION_MULTI_DEVICE: Long = 1L shl 2


    // full ratcheting thresholds
    val THRESHOLD_TIME_INTERVAL_SINCE_LAST_FULL_RATCHET_SENT_MESSAGE: Long =
        86400000L * 30 // restart the full ratchet after 30 days if it did not finish
    const val THRESHOLD_NUMBER_OF_ENCRYPTED_MESSAGES_PER_FULL_RATCHET: Int =
        500 // do a full ratchet after 500 messages
    val FULL_RATCHET_TIME_INTERVAL_VALIDITY: Long = 86400000L * 30 // do a full ratchet every month

    const val REPROVISIONING_THRESHOLD: Int = 50
    val PROVISIONED_KEY_MATERIAL_EXPIRATION_DELAY: Long =
        86400000L * 60 // expire old ProvisionedKeyMaterial after 60 days (same as server expiration)

    val OUTBOX_MESSAGE_MAX_SEND_DELAY: Long =
        86400000L * 30 // after 30 days without being able to upload a message, delete it
    val PROTOCOL_RECEIVED_MESSAGE_EXPIRATION_DELAY: Long =
        86400000L * 15 // expire ReceivedMessage after 15 days
    val SERVER_QUERY_EXPIRATION_DELAY: Long =
        86400000L * 30 // expire PendingServerQuery after 30 days
    val RETURN_RECEIPT_EXPIRATION_DELAY: Long =
        86400000L * 60 // delete ReturnReceipt after 60 days if it could not be uploaded
    val GROUP_V2_PRE_SHOT_VERSION_SEED_TTL: Long =
        86400000L * 60 // expire PreShotVersionSeed after 60 days

    val USER_DATA_REFRESH_INTERVAL: Long = 86400000L * 7 // 7 days
    val GET_USER_DATA_LOCAL_FILE_LIFESPAN: Long = 86400000L * 7 // 7 days
    val WELL_KNOWN_REFRESH_INTERVAL: Long = 3600000L * 6 // 6 hours

    // download message
    //    public static final long RELIST_DELAY = 10_000; // 10 seconds
    const val MINIMUM_URL_REFRESH_INTERVAL: Long = 3600000L // 1 hour

    // backups
    const val AUTOBACKUP_MAX_INTERVAL: Long = 86400000L // 1 day
    val AUTOBACKUP_START_DELAY: Long = 60000L * 2 // 2 minutes

    // not used for now
    //    public static final long PERIODIC_OWNED_DEVICE_SYNC_INTERVAL = 86_400_000L; // 1 day
    // backups v2
    val DEVICE_BACKUP_THREAD_ID: UID = UID(
        byteArrayOf(
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte(),
            0xfe.toByte()
        )
    )
    val DEVICE_BACKUP_INTERVAL: Long = 30 * 86400000L // 30 days
    const val PROFILE_BACKUP_INTERVAL: Long = 86400000L // 1 day
    val BACKUP_START_DELAY: Long = 5 * 60000L // 5 minutes

    // pre keys
    val PRE_KEY_VALIDITY_DURATION: Long =
        60 * 86400000L // validity duration of newly generated pre-keys: 60 days
    val PRE_KEY_RENEWAL_INTERVAL: Long =
        7 * 86400000L // how frequently to refresh pre-keys on the server: 7 days
    val PRE_KEY_CONSERVATION_DURATION: Long =
        60 * 86400000L // how long to keep a pre-key after it expires: 60 days
    val PRE_KEY_INBOX_NO_CONTACT_DURATION: Long =
        15 * 86400000L // how long to keep a message in the inbox if it can be decrypted with a pre-key, but the sender is not a contact: 15 days

    // device discovery
    val NO_DEVICE_CONTACT_DEVICE_DISCOVERY_INTERVAL: Long = 3 * 86400000L
    val CONTACT_DEVICE_DISCOVERY_INTERVAL: Long = 7 * 86400000L
    const val OWNED_DEVICE_DISCOVERY_INTERVAL: Long = 86400000L
    val CHANNEL_CREATION_PING_INTERVAL: Long = 30 * 86400000L

    const val SERVER_SESSION_NONCE_LENGTH: Int = 32
    const val SERVER_SESSION_CHALLENGE_LENGTH: Int = 32
    const val SERVER_SESSION_TOKEN_LENGTH: Int = 32

    const val RETURN_RECEIPT_NONCE_LENGTH: Int = 16

    const val GROUP_V2_INVITATION_NONCE_LENGTH: Int = 16
    const val GROUP_V2_LOCK_NONCE_LENGTH: Int = 32

    val DEFAULT_ATTACHMENT_CHUNK_LENGTH: Int = 4 * 2048 * 1024
    val MAX_MESSAGE_EXTENDED_CONTENT_LENGTH: Int = 50 * 1024
    const val MAX_UPLOAD_MESSAGE_BATCH_SIZE: Int = 50
    const val MAX_UPLOAD_MESSAGE_BATCH_HEADER_COUNT: Int = 1000
    const val MAX_UPLOAD_RETURN_RECEIPT_BATCH_SIZE: Int = 50
    const val MAX_DELETE_MESSAGE_ON_SERVER_BATCH_SIZE: Int = 50

    val BROADCAST_UID: UID = UID(
        byteArrayOf(
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte(),
            0xff.toByte()
        )
    )


    val ANDROID_STORE_ID: ByteArray = byteArrayOf(0x01)

    const val DEFAULT_NUMBER_OF_DIGITS_FOR_SAS: Int = 4
    const val EPHEMERAL_IDENTITY_SERVER: String = "ephemeral_fake_server"
    const val TRANSFER_WS_SERVER_URL: String = "wss://transfer.olvid.io"
    const val TRANSFER_MAX_PAYLOAD_SIZE: Int = 10000


    const val BASE_RESCHEDULING_TIME: Long = 250L
    const val WEBSOCKET_PING_INTERVAL_MILLIS: Long = 20000L
    const val WEBSOCKET_RECONNECT_INTERVAL_MILLIS: Long = 6000000L // 1h40 (the AWS timeout is 2h)
    const val WEBSOCKET_SLEEP_DETECTION_INTERVAL_MILLIS: Long = 5000L
    const val WEBSOCKET_SLEEP_DETECTION_THRESHOLD_MILLIS: Long = 10000L


    // Keycloak
    val KEYCLOAK_SIGNATURE_VALIDITY_MILLIS: Long = 60 * 86400000L


    // prefixes for various types of signature
    const val SIGNATURE_PADDING_LENGTH: Int = 16

    val SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "authentChallenge".toByteArray(
            StandardCharsets.UTF_8
        )
    val MUTUAL_SCAN_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "mutualScan".toByteArray(
        StandardCharsets.UTF_8
    )
    val MUTUAL_INTRODUCTION_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "mutualIntroduction".toByteArray(
            StandardCharsets.UTF_8
        )
    val CHANNEL_CREATION_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "channelCreation".toByteArray(
        StandardCharsets.UTF_8
    )
    val GROUP_ADMINISTRATORS_CHAIN_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "groupAdministratorsChain".toByteArray(
            StandardCharsets.UTF_8
        )
    val GROUP_BLOB_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "groupBlob".toByteArray(StandardCharsets.UTF_8)
    val GROUP_LEAVE_NONCE_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "groupLeave".toByteArray(
        StandardCharsets.UTF_8
    )
    val GROUP_LOCK_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "lockNonce".toByteArray(StandardCharsets.UTF_8)
    val GROUP_DELETE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "deleteGroup".toByteArray(
        StandardCharsets.UTF_8
    )
    val GROUP_JOIN_NONCE_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "joinGroup".toByteArray(
        StandardCharsets.UTF_8
    )
    val GROUP_UPDATE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "updateGroup".toByteArray(
        StandardCharsets.UTF_8
    )
    val GROUP_KICK_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "groupKick".toByteArray(StandardCharsets.UTF_8)
    val OWNED_IDENTITY_DELETION_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "ownedIdentityDeletion".toByteArray(
            StandardCharsets.UTF_8
        )
    val DEVICE_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "devicePreKey".toByteArray(
        StandardCharsets.UTF_8
    )
    val ENCRYPTION_WITH_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX: ByteArray =
        "encryptionWithPreKey".toByteArray(
            StandardCharsets.UTF_8
        )
    val BACKUP_UPLOAD_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "backupUpload".toByteArray(
        StandardCharsets.UTF_8
    )
    val BACKUP_DELETE_SIGNATURE_CHALLENGE_PREFIX: ByteArray = "backupDelete".toByteArray(
        StandardCharsets.UTF_8
    )
    val KEYCLOAK_ID_BASED_AUTH_CHALLENGE_PREFIX: ByteArray = "keycloakChallenge".toByteArray(
        StandardCharsets.UTF_8
    )

    @JvmStatic
    fun getSignatureChallengePrefix(signatureContext: SignatureContext): ByteArray {
        when (signatureContext) {
            SignatureContext.SERVER_AUTHENTICATION -> return SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.MUTUAL_SCAN -> return MUTUAL_SCAN_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.MUTUAL_INTRODUCTION -> return MUTUAL_INTRODUCTION_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.CHANNEL_CREATION -> return CHANNEL_CREATION_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_ADMINISTRATORS_CHAIN -> return GROUP_ADMINISTRATORS_CHAIN_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_BLOB -> return GROUP_BLOB_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_LEAVE_NONCE -> return GROUP_LEAVE_NONCE_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_LOCK_ON_SERVER -> return GROUP_LOCK_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_DELETE_ON_SERVER -> return GROUP_DELETE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_JOIN_NONCE -> return GROUP_JOIN_NONCE_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_UPDATE_ON_SERVER -> return GROUP_UPDATE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.GROUP_KICK -> return GROUP_KICK_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.OWNED_IDENTITY_DELETION -> return OWNED_IDENTITY_DELETION_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.DEVICE_PRE_KEY -> return DEVICE_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.ENCRYPTION_WITH_PRE_KEY -> return ENCRYPTION_WITH_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.BACKUP_UPLOAD -> return BACKUP_UPLOAD_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.BACKUP_DELETE -> return BACKUP_DELETE_SIGNATURE_CHALLENGE_PREFIX
            SignatureContext.KEYCLOAK_ID_BASED_AUTH -> return KEYCLOAK_ID_BASED_AUTH_CHALLENGE_PREFIX
        }
    }

    enum class SignatureContext {
        SERVER_AUTHENTICATION,
        MUTUAL_SCAN,
        MUTUAL_INTRODUCTION,
        CHANNEL_CREATION,
        GROUP_ADMINISTRATORS_CHAIN,
        GROUP_BLOB,
        GROUP_LEAVE_NONCE,
        GROUP_LOCK_ON_SERVER,
        GROUP_DELETE_ON_SERVER,
        GROUP_JOIN_NONCE,
        GROUP_UPDATE_ON_SERVER,
        GROUP_KICK,
        OWNED_IDENTITY_DELETION,
        DEVICE_PRE_KEY,
        ENCRYPTION_WITH_PRE_KEY,
        BACKUP_UPLOAD,
        BACKUP_DELETE,
        KEYCLOAK_ID_BASED_AUTH,
    }
}
