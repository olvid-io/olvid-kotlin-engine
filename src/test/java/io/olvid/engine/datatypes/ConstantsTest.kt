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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import java.nio.charset.StandardCharsets

/**
 * Characterization tests for [Constants].
 *
 * Every constant in [Constants] is a WIRE-FORMAT or PERSISTENCE value. Changing any one of
 * them silently breaks cryptographic signatures, server protocol parsing, or stored DB state.
 * This exhaustive pin is the documentation of those contracts.
 *
 * Tests are grouped by category:
 *  1. Signature challenge prefixes (18 byte[] wire-format values)
 *  2. getSignatureChallengePrefix dispatch table (18 enum → prefix mappings)
 *  3. SignatureContext enum count (guards against silent addition/removal)
 *  4. API_KEY_STATUS_* integer constants (server wire values)
 *  5. API_KEY_PERMISSION_* bitmask longs
 *  6. Wire-version constants (DB schema, server API, backup format)
 *  7. File/folder name constants (embedded in stored paths)
 *  8. Magic UID constants (32-byte arrays with sentinel values)
 *  9. Padding / SAS / nonce length constants
 * 10. Chunk / batch size constants
 * 11. Transfer constants
 * 12. Time-interval constants (sampled critical ones)
 */
class ConstantsTest {

    // ─── Group 1: Signature challenge prefixes ────────────────────────────────
    //
    // Each prefix is prepended to a challenge before signing. The exact UTF-8 bytes
    // must match what the server expects. A single character change invalidates all
    // signatures that use that prefix.

    @Test
    fun testServerAuthenticationSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "authentChallenge".toByteArray(StandardCharsets.UTF_8),
            Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testMutualScanSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "mutualScan".toByteArray(StandardCharsets.UTF_8),
            Constants.MUTUAL_SCAN_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testMutualIntroductionSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "mutualIntroduction".toByteArray(StandardCharsets.UTF_8),
            Constants.MUTUAL_INTRODUCTION_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testChannelCreationSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "channelCreation".toByteArray(StandardCharsets.UTF_8),
            Constants.CHANNEL_CREATION_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupAdministratorsChainSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "groupAdministratorsChain".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_ADMINISTRATORS_CHAIN_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupBlobSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "groupBlob".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_BLOB_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupLeaveNonceSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "groupLeave".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_LEAVE_NONCE_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupLockSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "lockNonce".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_LOCK_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupDeleteOnServerSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "deleteGroup".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_DELETE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupJoinNonceSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "joinGroup".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_JOIN_NONCE_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupUpdateOnServerSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "updateGroup".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_UPDATE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testGroupKickSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "groupKick".toByteArray(StandardCharsets.UTF_8),
            Constants.GROUP_KICK_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testOwnedIdentityDeletionSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "ownedIdentityDeletion".toByteArray(StandardCharsets.UTF_8),
            Constants.OWNED_IDENTITY_DELETION_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testDevicePreKeySignatureChallengePrefixBytes() {
        assertArrayEquals(
            "devicePreKey".toByteArray(StandardCharsets.UTF_8),
            Constants.DEVICE_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testEncryptionWithPreKeySignatureChallengePrefixBytes() {
        assertArrayEquals(
            "encryptionWithPreKey".toByteArray(StandardCharsets.UTF_8),
            Constants.ENCRYPTION_WITH_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testBackupUploadSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "backupUpload".toByteArray(StandardCharsets.UTF_8),
            Constants.BACKUP_UPLOAD_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testBackupDeleteSignatureChallengePrefixBytes() {
        assertArrayEquals(
            "backupDelete".toByteArray(StandardCharsets.UTF_8),
            Constants.BACKUP_DELETE_SIGNATURE_CHALLENGE_PREFIX,
        )
    }

    @Test
    fun testKeycloakIdBasedAuthChallengePrefixBytes() {
        assertArrayEquals(
            "keycloakChallenge".toByteArray(StandardCharsets.UTF_8),
            Constants.KEYCLOAK_ID_BASED_AUTH_CHALLENGE_PREFIX,
        )
    }

    // ─── Group 2: getSignatureChallengePrefix dispatch table ──────────────────
    //
    // Each test calls getSignatureChallengePrefix with a SignatureContext enum value and
    // asserts that the returned reference is the SAME OBJECT (assertSame) as the
    // corresponding *_SIGNATURE_CHALLENGE_PREFIX field. This pins:
    //   (a) the enum → prefix mapping (no accidental swap), and
    //   (b) that the method returns the field reference directly (no copy).

    @Test
    fun testGetSignatureChallengePrefixForServerAuthentication() {
        assertSame(
            Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.SERVER_AUTHENTICATION),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForMutualScan() {
        assertSame(
            Constants.MUTUAL_SCAN_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.MUTUAL_SCAN),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForMutualIntroduction() {
        assertSame(
            Constants.MUTUAL_INTRODUCTION_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.MUTUAL_INTRODUCTION),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForChannelCreation() {
        assertSame(
            Constants.CHANNEL_CREATION_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.CHANNEL_CREATION),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupAdministratorsChain() {
        assertSame(
            Constants.GROUP_ADMINISTRATORS_CHAIN_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_ADMINISTRATORS_CHAIN),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupBlob() {
        assertSame(
            Constants.GROUP_BLOB_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_BLOB),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupLeaveNonce() {
        assertSame(
            Constants.GROUP_LEAVE_NONCE_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_LEAVE_NONCE),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupLockOnServer() {
        // SignatureContext.GROUP_LOCK_ON_SERVER maps to GROUP_LOCK_SIGNATURE_CHALLENGE_PREFIX
        assertSame(
            Constants.GROUP_LOCK_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_LOCK_ON_SERVER),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupDeleteOnServer() {
        assertSame(
            Constants.GROUP_DELETE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_DELETE_ON_SERVER),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupJoinNonce() {
        assertSame(
            Constants.GROUP_JOIN_NONCE_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_JOIN_NONCE),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupUpdateOnServer() {
        assertSame(
            Constants.GROUP_UPDATE_ON_SERVER_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_UPDATE_ON_SERVER),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForGroupKick() {
        assertSame(
            Constants.GROUP_KICK_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.GROUP_KICK),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForOwnedIdentityDeletion() {
        assertSame(
            Constants.OWNED_IDENTITY_DELETION_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.OWNED_IDENTITY_DELETION),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForDevicePreKey() {
        assertSame(
            Constants.DEVICE_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.DEVICE_PRE_KEY),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForEncryptionWithPreKey() {
        assertSame(
            Constants.ENCRYPTION_WITH_PRE_KEY_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.ENCRYPTION_WITH_PRE_KEY),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForBackupUpload() {
        assertSame(
            Constants.BACKUP_UPLOAD_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.BACKUP_UPLOAD),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForBackupDelete() {
        assertSame(
            Constants.BACKUP_DELETE_SIGNATURE_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.BACKUP_DELETE),
        )
    }

    @Test
    fun testGetSignatureChallengePrefixForKeycloakIdBasedAuth() {
        assertSame(
            Constants.KEYCLOAK_ID_BASED_AUTH_CHALLENGE_PREFIX,
            Constants.getSignatureChallengePrefix(Constants.SignatureContext.KEYCLOAK_ID_BASED_AUTH),
        )
    }

    // ─── Group 3: SignatureContext enum count ─────────────────────────────────
    //
    // Pins the total number of enum values. Adding or removing a SignatureContext
    // without updating the dispatch table and prefix fields is a bug; this test
    // makes such changes immediately visible.

    @Test
    fun testSignatureContextEnumHasExactly18Values() {
        assertEquals(18, Constants.SignatureContext.values().size)
    }

    // ─── Group 4: API_KEY_STATUS_* integer constants ──────────────────────────
    //
    // These values are sent by the server and stored in the DB. A change to any
    // value causes the wrong status to be decoded from server responses or existing rows.

    @Test
    fun testApiKeyStatusValidIsExactly0() {
        assertEquals(0, Constants.API_KEY_STATUS_VALID)
    }

    @Test
    fun testApiKeyStatusUnknownIsExactly1() {
        assertEquals(1, Constants.API_KEY_STATUS_UNKNOWN)
    }

    @Test
    fun testApiKeyStatusLicensesExhaustedIsExactly2() {
        assertEquals(2, Constants.API_KEY_STATUS_LICENSES_EXHAUSTED)
    }

    @Test
    fun testApiKeyStatusExpiredIsExactly3() {
        assertEquals(3, Constants.API_KEY_STATUS_EXPIRED)
    }

    @Test
    fun testApiKeyStatusOpenBetaKeyIsExactly4() {
        assertEquals(4, Constants.API_KEY_STATUS_OPEN_BETA_KEY)
    }

    @Test
    fun testApiKeyStatusFreeTrialKeyIsExactly5() {
        assertEquals(5, Constants.API_KEY_STATUS_FREE_TRIAL_KEY)
    }

    @Test
    fun testApiKeyStatusAwaitingPaymentGracePeriodIsExactly6() {
        assertEquals(6, Constants.API_KEY_STATUS_AWAITING_PAYMENT_GRACE_PERIOD)
    }

    @Test
    fun testApiKeyStatusAwaitingPaymentOnHoldIsExactly7() {
        assertEquals(7, Constants.API_KEY_STATUS_AWAITING_PAYMENT_ON_HOLD)
    }

    @Test
    fun testApiKeyStatusFreeTrialKeyExpiredIsExactly8() {
        assertEquals(8, Constants.API_KEY_STATUS_FREE_TRIAL_KEY_EXPIRED)
    }

    // ─── Group 5: API_KEY_PERMISSION_* bitmask longs ─────────────────────────
    //
    // These are individual bits of a permissions long sent by the server. Bit positions
    // must not shift. A change to any value silently grants or revokes a feature.

    @Test
    fun testApiKeyPermissionCallIs1() {
        // Bit 0 (1L << 0)
        assertEquals(1L, Constants.API_KEY_PERMISSION_CALL)
    }

    @Test
    fun testApiKeyPermissionWebClientIs2() {
        // Bit 1 (1L << 1)
        assertEquals(2L, Constants.API_KEY_PERMISSION_WEB_CLIENT)
    }

    @Test
    fun testApiKeyPermissionMultiDeviceIs4() {
        // Bit 2 (1L << 2)
        assertEquals(4L, Constants.API_KEY_PERMISSION_MULTI_DEVICE)
    }

    // ─── Group 6: Wire-version constants ─────────────────────────────────────
    //
    // DB schema version is embedded in every migrated database. Server API version is
    // negotiated on connection. Backup JSON version is stored in backup files.
    // All three must remain stable across migrations.

    @Test
    fun testCurrentEngineDbSchemaVersionIsExactly52() {
        // Bumped 51 -> 52 by the UI-dialog version-guard change (received_message.user_dialog_version).
        assertEquals(52, Constants.CURRENT_ENGINE_DB_SCHEMA_VERSION)
    }

    @Test
    fun testServerApiVersionIsExactly21() {
        assertEquals(21, Constants.SERVER_API_VERSION)
    }

    @Test
    fun testCurrentBackupJsonVersionIsExactly0() {
        assertEquals(0, Constants.CURRENT_BACKUP_JSON_VERSION)
    }

    // ─── Group 7: File/folder name constants ─────────────────────────────────
    //
    // These strings are embedded in file paths stored on disk. If any string changes,
    // the engine loses track of existing stored files (attachments, photos, user data).

    @Test
    fun testEngineDbFilenameIsExact() {
        assertEquals("engine_db.sqlite", Constants.ENGINE_DB_FILENAME)
    }

    @Test
    fun testTmpEngineEncryptedDbFilenameIsExact() {
        assertEquals("engine_encrypted_db.sqlite", Constants.TMP_ENGINE_ENCRYPTED_DB_FILENAME)
    }

    @Test
    fun testInboundAttachmentsDirectoryIsExact() {
        assertEquals("inbound_attachments", Constants.INBOUND_ATTACHMENTS_DIRECTORY)
    }

    @Test
    fun testIdentityPhotosDirectoryIsExact() {
        assertEquals("identity_photos", Constants.IDENTITY_PHOTOS_DIRECTORY)
    }

    @Test
    fun testDownloadedUserDataDirectoryIsExact() {
        assertEquals("downloaded_user_data", Constants.DOWNLOADED_USER_DATA_DIRECTORY)
    }

    // ─── Group 8: Magic UID constants ────────────────────────────────────────
    //
    // BROADCAST_UID and DEVICE_BACKUP_THREAD_ID are sentinel 32-byte values with fixed
    // bit patterns. If the pattern changes, broadcast messages are misrouted and backup
    // thread identification breaks. ANDROID_STORE_ID is a 1-byte store identifier
    // sent to the server.

    @Test
    fun testBroadcastUidIs32BytesOf0xff() {
        val expected = ByteArray(32) { 0xff.toByte() }
        assertArrayEquals(expected, Constants.BROADCAST_UID.bytes)
    }

    @Test
    fun testDeviceBackupThreadIdIs32BytesOf0xfe() {
        val expected = ByteArray(32) { 0xfe.toByte() }
        assertArrayEquals(expected, Constants.DEVICE_BACKUP_THREAD_ID.bytes)
    }

    @Test
    fun testAndroidStoreIdIs0x01() {
        assertArrayEquals(byteArrayOf(0x01), Constants.ANDROID_STORE_ID)
    }

    // ─── Group 9: Padding / SAS / nonce length constants ─────────────────────
    //
    // These lengths govern the size of cryptographic material. A wrong value causes
    // interoperability failures or security regressions.

    @Test
    fun testSignaturePaddingLengthIs16() {
        assertEquals(16, Constants.SIGNATURE_PADDING_LENGTH)
    }

    @Test
    fun testDefaultNumberOfDigitsForSasIs4() {
        assertEquals(4, Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS)
    }

    @Test
    fun testServerSessionNonceLengthIs32() {
        assertEquals(32, Constants.SERVER_SESSION_NONCE_LENGTH)
    }

    @Test
    fun testServerSessionChallengeLengthIs32() {
        assertEquals(32, Constants.SERVER_SESSION_CHALLENGE_LENGTH)
    }

    @Test
    fun testServerSessionTokenLengthIs32() {
        assertEquals(32, Constants.SERVER_SESSION_TOKEN_LENGTH)
    }

    @Test
    fun testReturnReceiptNonceLengthIs16() {
        assertEquals(16, Constants.RETURN_RECEIPT_NONCE_LENGTH)
    }

    @Test
    fun testGroupV2InvitationNonceLengthIs16() {
        assertEquals(16, Constants.GROUP_V2_INVITATION_NONCE_LENGTH)
    }

    @Test
    fun testGroupV2LockNonceLengthIs32() {
        assertEquals(32, Constants.GROUP_V2_LOCK_NONCE_LENGTH)
    }

    // ─── Group 10: Chunk / batch size constants ───────────────────────────────
    //
    // Attachment chunk size governs upload/download fragmentation. Batch size constants
    // limit how many items are sent per server request. Changing any value changes server
    // protocol behaviour and may cause rejection or silent data loss.

    @Test
    fun testDefaultAttachmentChunkLengthIs8388608() {
        // 4 * 2048 * 1024
        assertEquals(4 * 2048 * 1024, Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH)
    }

    @Test
    fun testMaxMessageExtendedContentLengthIs51200() {
        // 50 * 1024
        assertEquals(50 * 1024, Constants.MAX_MESSAGE_EXTENDED_CONTENT_LENGTH)
    }

    @Test
    fun testMaxUploadMessageBatchSizeIs50() {
        assertEquals(50, Constants.MAX_UPLOAD_MESSAGE_BATCH_SIZE)
    }

    @Test
    fun testMaxUploadMessageBatchHeaderCountIs1000() {
        assertEquals(1_000, Constants.MAX_UPLOAD_MESSAGE_BATCH_HEADER_COUNT)
    }

    @Test
    fun testMaxUploadReturnReceiptBatchSizeIs50() {
        assertEquals(50, Constants.MAX_UPLOAD_RETURN_RECEIPT_BATCH_SIZE)
    }

    @Test
    fun testMaxDeleteMessageOnServerBatchSizeIs50() {
        assertEquals(50, Constants.MAX_DELETE_MESSAGE_ON_SERVER_BATCH_SIZE)
    }

    // ─── Group 11: Transfer constants ────────────────────────────────────────
    //
    // EPHEMERAL_IDENTITY_SERVER is stored as the server URL for ephemeral identities
    // used during identity transfer. TRANSFER_WS_SERVER_URL is the WebSocket endpoint.
    // TRANSFER_MAX_PAYLOAD_SIZE limits the transfer payload to avoid server rejection.

    @Test
    fun testEphemeralIdentityServerIsExact() {
        assertEquals("ephemeral_fake_server", Constants.EPHEMERAL_IDENTITY_SERVER)
    }

    @Test
    fun testTransferWsServerUrlIsExact() {
        assertEquals("wss://transfer.olvid.io", Constants.TRANSFER_WS_SERVER_URL)
    }

    @Test
    fun testTransferMaxPayloadSizeIs10000() {
        assertEquals(10000, Constants.TRANSFER_MAX_PAYLOAD_SIZE)
    }

    // ─── Group 12: Time-interval constants (critical sampling) ────────────────
    //
    // These govern ratchet scheduling, session management, and network reconnection
    // timing. Incorrect values cause either security regressions (too-long ratchet
    // intervals) or excessive server load (too-short ping intervals).

    @Test
    fun testThresholdNumberOfEncryptedMessagesPerFullRatchetIs500() {
        assertEquals(500, Constants.THRESHOLD_NUMBER_OF_ENCRYPTED_MESSAGES_PER_FULL_RATCHET)
    }

    @Test
    fun testReprovisioningThresholdIs50() {
        assertEquals(50, Constants.REPROVISIONING_THRESHOLD)
    }

    @Test
    fun testMinimumUrlRefreshIntervalIs3600000() {
        // 1 hour in milliseconds
        assertEquals(3_600_000L, Constants.MINIMUM_URL_REFRESH_INTERVAL)
    }

    @Test
    fun testWebsocketPingIntervalMillisIs20000() {
        assertEquals(20_000L, Constants.WEBSOCKET_PING_INTERVAL_MILLIS)
    }

    @Test
    fun testBaseReschedulingTimeIs250() {
        assertEquals(250L, Constants.BASE_RESCHEDULING_TIME)
    }
}
