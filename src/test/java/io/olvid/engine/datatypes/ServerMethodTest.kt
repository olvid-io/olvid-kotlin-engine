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

import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Characterization tests for [ServerMethod] and [ServerMethodForS3].
 *
 * These tests pin the wire-format byte constants that are exchanged between the Android client
 * and the Olvid server. A Java→Kotlin migration that silently renumbers any constant will break
 * error-handling dispatch without a compilation error; these tests catch that.
 *
 * ## ServerMethod constant taxonomy
 *
 * Server-protocol status codes (0x00..0x1d) — byte values returned by the Olvid server in the
 * first element of each response list. The server encodes exactly these byte values on the wire.
 *
 * Local error codes (0x80..0xff, high bit set) — synthesised by the client when the HTTP
 * layer or response parser fails before any server byte is read.
 *
 * ### Commented-out wire-format codes (NOT declared as constants, NOT tested)
 * The following values are reserved by the server protocol and the server may still emit them,
 * but the current Android client does not consume them:
 *   - PROOF_OF_WORK_REQUIRED          = 0x01
 *   - QUOTA_EXCEEDED                  = 0x02
 *   - EXCEEDING_EXPECTED_BYTE_LENGTH  = 0x03
 *   - NOT_YET_AVAILABLE               = 0x05
 *   - MESSAGE_NOT_COMPLETE_YET        = 0x06
 *   - UNKNOWN_API_KEY                 = 0x07
 *   - API_KEY_LICENSES_EXHAUSTED      = 0x08
 *   - UPLOAD_CANCELLED                = 0x0d
 *   - STATUS_RECEIPT_IS_EXPIRED       = 0x10  (iOS only)
 * These are not pinned here because they are not declared constants in ServerMethod.
 *
 * ## What is NOT tested
 * - execute() — requires a real network or a stubbed HttpsURLConnection.
 * - Abstract method contracts (getServer, getServerMethod, getDataToSend,
 *   parseReceivedData, isActiveIdentityRequired) — these are compile-time contracts.
 * - Logger call-sites.
 */
class ServerMethodTest {

    // ─── Minimal concrete subclass ─────────────────────────────────────────────

    /**
     * Minimal concrete subclass used only to test the inherited [returnStatus] default value.
     * All five abstract methods return the simplest legal stub value.
     */
    private class TestServerMethod : ServerMethod() {
        override fun getServer(): String = "test.olvid.io"
        override fun getServerMethod(): String = "/test"
        override fun getDataToSend(): ByteArray = byteArrayOf()
        override fun parseReceivedData(receivedData: Array<Encoded?>?) {}
        override fun isActiveIdentityRequired(): Boolean = false
    }

    // ─── Group 1: Server-protocol status byte constants ───────────────────────
    //
    // Each assertEquals pins the exact wire-format byte value. The server returns this
    // exact byte in the first element of each response list. A Kotlin migration that
    // accidentally renumbers any constant silently breaks all error-handling dispatch.

    @Test
    fun testOk_isExactly0x00() {
        assertEquals(0x00.toByte(), ServerMethod.OK)
    }

    @Test
    fun testInvalidSession_isExactly0x04() {
        assertEquals(0x04.toByte(), ServerMethod.INVALID_SESSION)
    }

    @Test
    fun testDeletedFromServer_isExactly0x09() {
        assertEquals(0x09.toByte(), ServerMethod.DELETED_FROM_SERVER)
    }

    @Test
    fun testAnotherDeviceIsAlreadyRegistered_isExactly0x0a() {
        assertEquals(0x0a.toByte(), ServerMethod.ANOTHER_DEVICE_IS_ALREADY_REGISTERED)
    }

    @Test
    fun testDeviceIsNotRegistered_isExactly0x0b() {
        assertEquals(0x0b.toByte(), ServerMethod.DEVICE_IS_NOT_REGISTERED)
    }

    @Test
    fun testInvalidNonce_isExactly0x0c() {
        assertEquals(0x0c.toByte(), ServerMethod.INVALID_NONCE)
    }

    @Test
    fun testPermissionDenied_isExactly0x0e() {
        assertEquals(0x0e.toByte(), ServerMethod.PERMISSION_DENIED)
    }

    @Test
    fun testFreeTrialAlreadyUsed_isExactly0x0f() {
        assertEquals(0x0f.toByte(), ServerMethod.FREE_TRIAL_ALREADY_USED)
    }

    @Test
    fun testExtendedPayloadUnavailable_isExactly0x11() {
        assertEquals(0x11.toByte(), ServerMethod.EXTENDED_PAYLOAD_UNAVAILABLE)
    }

    @Test
    fun testGroupUidAlreadyUsed_isExactly0x12() {
        assertEquals(0x12.toByte(), ServerMethod.GROUP_UID_ALREADY_USED)
    }

    @Test
    fun testGroupIsLocked_isExactly0x13() {
        assertEquals(0x13.toByte(), ServerMethod.GROUP_IS_LOCKED)
    }

    @Test
    fun testInvalidSignature_isExactly0x14() {
        assertEquals(0x14.toByte(), ServerMethod.INVALID_SIGNATURE)
    }

    @Test
    fun testGroupNotLocked_isExactly0x15() {
        assertEquals(0x15.toByte(), ServerMethod.GROUP_NOT_LOCKED)
    }

    @Test
    fun testInvalidApiKey_isExactly0x16() {
        assertEquals(0x16.toByte(), ServerMethod.INVALID_API_KEY)
    }

    @Test
    fun testListingTruncated_isExactly0x17() {
        assertEquals(0x17.toByte(), ServerMethod.LISTING_TRUNCATED)
    }

    @Test
    fun testPayloadTooLarge_isExactly0x18() {
        // Declared as (byte) 0x18 — would be 0x18 unsigned, -232 signed; the cast matters.
        assertEquals(0x18.toByte(), ServerMethod.PAYLOAD_TOO_LARGE)
    }

    @Test
    fun testBackupUidAlreadyUsed_isExactly0x19() {
        assertEquals(0x19.toByte(), ServerMethod.BACKUP_UID_ALREADY_USED)
    }

    @Test
    fun testBackupVersionTooSmall_isExactly0x1a() {
        assertEquals(0x1a.toByte(), ServerMethod.BACKUP_VERSION_TOO_SMALL)
    }

    @Test
    fun testUnknownBackupUid_isExactly0x1b() {
        assertEquals(0x1b.toByte(), ServerMethod.UNKNOWN_BACKUP_UID)
    }

    @Test
    fun testUnknownBackupThreadId_isExactly0x1c() {
        assertEquals(0x1c.toByte(), ServerMethod.UNKNOWN_BACKUP_THREAD_ID)
    }

    @Test
    fun testUnknownBackupVersion_isExactly0x1d() {
        assertEquals(0x1d.toByte(), ServerMethod.UNKNOWN_BACKUP_VERSION)
    }

    // ─── Group 2: Local error byte constants (high bit set) ───────────────────
    //
    // These are synthesised by the client — never sent by the server. The high bit (0x80)
    // separates them from server-protocol codes. All must remain >= 0x80 (unsigned).

    @Test
    fun testMalformedUrl_isExactly0x80() {
        assertEquals(0x80.toByte(), ServerMethod.MALFORMED_URL)
    }

    @Test
    fun testServerConnectionError_isExactly0x81() {
        assertEquals(0x81.toByte(), ServerMethod.SERVER_CONNECTION_ERROR)
    }

    @Test
    fun testMalformedServerResponse_isExactly0x82() {
        assertEquals(0x82.toByte(), ServerMethod.MALFORMED_SERVER_RESPONSE)
    }

    @Test
    fun testOkWithMalformedServerResponse_isExactly0x83() {
        assertEquals(0x83.toByte(), ServerMethod.OK_WITH_MALFORMED_SERVER_RESPONSE)
    }

    @Test
    fun testIdentityIsNotActive_isExactly0x8e() {
        assertEquals(0x8e.toByte(), ServerMethod.IDENTITY_IS_NOT_ACTIVE)
    }

    @Test
    fun testParsingError_isExactly0xfe() {
        assertEquals(0xfe.toByte(), ServerMethod.PARSING_ERROR)
    }

    @Test
    fun testGeneralError_isExactly0xff() {
        assertEquals(0xff.toByte(), ServerMethod.GENERAL_ERROR)
    }

    // ─── Group 3: Partition — server codes below 0x80, local codes at/above 0x80 ─
    //
    // These two bulk assertions guard the high-bit partition that separates
    // server-protocol codes from locally-synthesised error codes.
    // A migration that moves any constant across the boundary silently breaks
    // client code that checks `returnStatus < 0` to detect local errors.

    @Test
    fun testAllServerProtocolCodesAreBelowHighBit() {
        // All active server-protocol status codes must have unsigned value < 0x80.
        // In signed Java bytes these are the non-negative values (0x00..0x7f).
        val serverCodes = listOf(
            ServerMethod.OK,
            ServerMethod.INVALID_SESSION,
            ServerMethod.DELETED_FROM_SERVER,
            ServerMethod.ANOTHER_DEVICE_IS_ALREADY_REGISTERED,
            ServerMethod.DEVICE_IS_NOT_REGISTERED,
            ServerMethod.INVALID_NONCE,
            ServerMethod.PERMISSION_DENIED,
            ServerMethod.FREE_TRIAL_ALREADY_USED,
            ServerMethod.EXTENDED_PAYLOAD_UNAVAILABLE,
            ServerMethod.GROUP_UID_ALREADY_USED,
            ServerMethod.GROUP_IS_LOCKED,
            ServerMethod.INVALID_SIGNATURE,
            ServerMethod.GROUP_NOT_LOCKED,
            ServerMethod.INVALID_API_KEY,
            ServerMethod.LISTING_TRUNCATED,
            ServerMethod.PAYLOAD_TOO_LARGE,
            ServerMethod.BACKUP_UID_ALREADY_USED,
            ServerMethod.BACKUP_VERSION_TOO_SMALL,
            ServerMethod.UNKNOWN_BACKUP_UID,
            ServerMethod.UNKNOWN_BACKUP_THREAD_ID,
            ServerMethod.UNKNOWN_BACKUP_VERSION,
        )
        for (code in serverCodes) {
            val unsigned = code.toInt() and 0xff
            assertTrue(
                "Server-protocol code 0x${unsigned.toString(16)} must be below 0x80 " +
                    "(unsigned), but was $unsigned",
                unsigned < 0x80,
            )
        }
    }

    @Test
    fun testAllLocalErrorCodesHaveHighBitSet() {
        // All locally-synthesised error codes must have unsigned value >= 0x80 (high bit set).
        // In signed Java bytes these appear as negative values.
        val localCodes = listOf(
            ServerMethod.MALFORMED_URL,
            ServerMethod.SERVER_CONNECTION_ERROR,
            ServerMethod.MALFORMED_SERVER_RESPONSE,
            ServerMethod.OK_WITH_MALFORMED_SERVER_RESPONSE,
            ServerMethod.IDENTITY_IS_NOT_ACTIVE,
            ServerMethod.PARSING_ERROR,
            ServerMethod.GENERAL_ERROR,
        )
        for (code in localCodes) {
            val unsigned = code.toInt() and 0xff
            assertTrue(
                "Local error code 0x${unsigned.toString(16)} must be >= 0x80 " +
                    "(high bit set), but was $unsigned",
                unsigned >= 0x80,
            )
        }
    }

    // ─── Group 4: returnStatus field defaults to 0 (== OK) after construction ──
    //
    // `returnStatus` is a protected byte in ServerMethod. Java byte primitives default
    // to 0, which equals OK (0x00). This is a load-bearing semantic: callers that check
    // `getReturnStatus() == OK` before calling execute() must see OK, not some garbage value.

    @Test
    fun testReturnStatus_defaultsToZeroAfterConstruction() {
        // Access via reflection — returnStatus is protected, not exposed by a public getter.
        val method = TestServerMethod()
        val field = ServerMethod::class.java.getDeclaredField("returnStatus")
        field.isAccessible = true
        val value = field.getByte(method)
        assertEquals(
            "returnStatus must default to 0 (== OK) immediately after construction",
            0.toByte(),
            value,
        )
    }

    // ─── Group 5: All active server codes are pairwise distinct ───────────────
    //
    // If two constants share the same byte value, one switch-case is dead code and error
    // handling for one status will silently be routed to the wrong handler.

    @Test
    fun testAllServerProtocolCodesArePairwiseDistinct() {
        val serverCodes = listOf(
            ServerMethod.OK,
            ServerMethod.INVALID_SESSION,
            ServerMethod.DELETED_FROM_SERVER,
            ServerMethod.ANOTHER_DEVICE_IS_ALREADY_REGISTERED,
            ServerMethod.DEVICE_IS_NOT_REGISTERED,
            ServerMethod.INVALID_NONCE,
            ServerMethod.PERMISSION_DENIED,
            ServerMethod.FREE_TRIAL_ALREADY_USED,
            ServerMethod.EXTENDED_PAYLOAD_UNAVAILABLE,
            ServerMethod.GROUP_UID_ALREADY_USED,
            ServerMethod.GROUP_IS_LOCKED,
            ServerMethod.INVALID_SIGNATURE,
            ServerMethod.GROUP_NOT_LOCKED,
            ServerMethod.INVALID_API_KEY,
            ServerMethod.LISTING_TRUNCATED,
            ServerMethod.PAYLOAD_TOO_LARGE,
            ServerMethod.BACKUP_UID_ALREADY_USED,
            ServerMethod.BACKUP_VERSION_TOO_SMALL,
            ServerMethod.UNKNOWN_BACKUP_UID,
            ServerMethod.UNKNOWN_BACKUP_THREAD_ID,
            ServerMethod.UNKNOWN_BACKUP_VERSION,
        )
        val distinct = serverCodes.toSet()
        assertEquals(
            "All ${serverCodes.size} active server-protocol status constants must have distinct byte values",
            serverCodes.size,
            distinct.size,
        )
    }

    @Test
    fun testAllLocalErrorCodesArePairwiseDistinct() {
        val localCodes = listOf(
            ServerMethod.MALFORMED_URL,
            ServerMethod.SERVER_CONNECTION_ERROR,
            ServerMethod.MALFORMED_SERVER_RESPONSE,
            ServerMethod.OK_WITH_MALFORMED_SERVER_RESPONSE,
            ServerMethod.IDENTITY_IS_NOT_ACTIVE,
            ServerMethod.PARSING_ERROR,
            ServerMethod.GENERAL_ERROR,
        )
        val distinct = localCodes.toSet()
        assertEquals(
            "All ${localCodes.size} local error constants must have distinct byte values",
            localCodes.size,
            distinct.size,
        )
    }
}

/**
 * Characterization tests for [ServerMethodForS3].
 *
 * ServerMethodForS3 handles S3-compatible object-storage operations (PUT for upload, GET for
 * download). It has its own small set of wire-format constants and two HTTP-method string constants
 * used to dispatch PUT vs GET logic inside execute().
 *
 * ## What is NOT tested
 * - execute() — requires a real network or a stubbed HttpURLConnection.
 * - Abstract method contracts (getUrl, getDataToSend, handleReceivedData, getMethod,
 *   isActiveIdentityRequired).
 * - Progress listener callbacks.
 * - Logger call-sites.
 */
class ServerMethodForS3Test {

    // ─── Minimal concrete subclass ─────────────────────────────────────────────

    private class TestServerMethodForS3 : ServerMethodForS3() {
        override fun getUrl(): String = "https://s3.example.com/bucket/key"
        override fun getDataToSend(): ByteArray = byteArrayOf()
        override fun handleReceivedData(receivedData: ByteArray?) {}
        override fun getMethod(): String = ServerMethodForS3.METHOD_GET
        override fun isActiveIdentityRequired(): Boolean = false
    }

    // ─── Group 1: Wire-format status byte constants ────────────────────────────

    @Test
    fun testOk_isExactly0x00() {
        assertEquals(0x00.toByte(), ServerMethodForS3.OK)
    }

    @Test
    fun testNotFound_isExactly0x01() {
        // Returned when the S3 object does not exist (HTTP 404).
        assertEquals(0x01.toByte(), ServerMethodForS3.NOT_FOUND)
    }

    @Test
    fun testInvalidSignedUrl_isExactly0x02() {
        // Returned when the pre-signed S3 URL is rejected (HTTP 403).
        assertEquals(0x02.toByte(), ServerMethodForS3.INVALID_SIGNED_URL)
    }

    @Test
    fun testGeneralError_isExactly0xff() {
        // Returned for any unexpected HTTP response code (not 200, 403, or 404).
        assertEquals(0xff.toByte(), ServerMethodForS3.GENERAL_ERROR)
    }

    // ─── Group 2: Local error byte constants (high bit set) ───────────────────

    @Test
    fun testMalformedUrl_isExactly0x80() {
        assertEquals(0x80.toByte(), ServerMethodForS3.MALFORMED_URL)
    }

    @Test
    fun testServerConnectionError_isExactly0x81() {
        assertEquals(0x81.toByte(), ServerMethodForS3.SERVER_CONNECTION_ERROR)
    }

    @Test
    fun testIdentityIsNotActive_isExactly0x8e() {
        assertEquals(0x8e.toByte(), ServerMethodForS3.IDENTITY_IS_NOT_ACTIVE)
    }

    // ─── Group 3: HTTP method string constants ─────────────────────────────────
    //
    // execute() dispatches on getMethod() using equals() comparisons with these exact strings.
    // A migration that changes the case or spelling silently breaks PUT/GET dispatch.

    @Test
    fun testMethodPut_isExactlyPUT() {
        assertEquals("PUT", ServerMethodForS3.METHOD_PUT)
    }

    @Test
    fun testMethodGet_isExactlyGET() {
        assertEquals("GET", ServerMethodForS3.METHOD_GET)
    }

    // ─── Group 4: Partition — S3 server codes are below 0x80 ──────────────────

    @Test
    fun testAllS3ServerCodesAreBelowHighBit() {
        // OK (0x00), NOT_FOUND (0x01), and INVALID_SIGNED_URL (0x02) are the server-side
        // codes; all must be below 0x80 so they don't collide with local error codes.
        val serverCodes = listOf(
            ServerMethodForS3.OK,
            ServerMethodForS3.NOT_FOUND,
            ServerMethodForS3.INVALID_SIGNED_URL,
        )
        for (code in serverCodes) {
            val unsigned = code.toInt() and 0xff
            assertTrue(
                "S3 server code 0x${unsigned.toString(16)} must be below 0x80, but was $unsigned",
                unsigned < 0x80,
            )
        }
    }

    @Test
    fun testAllS3LocalErrorCodesHaveHighBitSet() {
        val localCodes = listOf(
            ServerMethodForS3.MALFORMED_URL,
            ServerMethodForS3.SERVER_CONNECTION_ERROR,
            ServerMethodForS3.IDENTITY_IS_NOT_ACTIVE,
        )
        for (code in localCodes) {
            val unsigned = code.toInt() and 0xff
            assertTrue(
                "S3 local error code 0x${unsigned.toString(16)} must be >= 0x80, but was $unsigned",
                unsigned >= 0x80,
            )
        }
    }

    // ─── Group 5: returnStatus field defaults to 0 (== OK) after construction ──

    @Test
    fun testReturnStatus_defaultsToZeroAfterConstruction() {
        val method = TestServerMethodForS3()
        val field = ServerMethodForS3::class.java.getDeclaredField("returnStatus")
        field.isAccessible = true
        val value = field.getByte(method)
        assertEquals(
            "returnStatus must default to 0 (== OK) immediately after construction",
            0.toByte(),
            value,
        )
    }

    // ─── Group 6: All S3 status codes are pairwise distinct ───────────────────

    @Test
    fun testAllS3StatusCodesArePairwiseDistinct() {
        // Includes GENERAL_ERROR (0xff) even though it is a local/fallthrough code;
        // it must not collide with any of the three server-protocol codes.
        val allCodes = listOf(
            ServerMethodForS3.OK,
            ServerMethodForS3.NOT_FOUND,
            ServerMethodForS3.INVALID_SIGNED_URL,
            ServerMethodForS3.GENERAL_ERROR,
            ServerMethodForS3.MALFORMED_URL,
            ServerMethodForS3.SERVER_CONNECTION_ERROR,
            ServerMethodForS3.IDENTITY_IS_NOT_ACTIVE,
        )
        val distinct = allCodes.toSet()
        assertEquals(
            "All ${allCodes.size} ServerMethodForS3 status constants must have distinct byte values",
            allCodes.size,
            distinct.size,
        )
    }
}
