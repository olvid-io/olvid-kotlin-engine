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

package io.olvid.engine.engine.types

import io.olvid.engine.Logger
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvTransferStep.Fail
import io.olvid.engine.engine.types.ObvTransferStep.OngoingProtocol
import io.olvid.engine.engine.types.ObvTransferStep.SourceDisplaySessionNumber
import io.olvid.engine.engine.types.ObvTransferStep.SourceSasInput
import io.olvid.engine.engine.types.ObvTransferStep.SourceSnapshotSent
import io.olvid.engine.engine.types.ObvTransferStep.SourceWaitForSessionNumberStep
import io.olvid.engine.engine.types.ObvTransferStep.Step
import io.olvid.engine.engine.types.ObvTransferStep.TargetRequestsKeycloakAuthenticationProof
import io.olvid.engine.engine.types.ObvTransferStep.TargetSessionNumberInput
import io.olvid.engine.engine.types.ObvTransferStep.TargetShowSas
import io.olvid.engine.engine.types.ObvTransferStep.TargetSnapshotReceived
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Method

/**
 * Characterization tests for [ObvTransferStep].
 *
 * The integer values in the [Step] enum and the [Fail] reason constants are
 * WIRE FORMAT — they are encoded into [Encoded] bytes that are persisted and
 * transmitted. Any change to these values silently corrupts stored state-machine
 * progress or cross-device messages.
 *
 * Groups:
 *  1. Step enum integer IDs — pin each Step.value (10 tests)
 *  2. Step.fromIntValue mapping — valid and unknown inputs (14 tests)
 *  3. Fail reason constants — pin each FAIL_REASON_* int (4 tests)
 *  4. Step enum count — exactly 10 declared constants (1 test)
 *  5. of(Encoded) dispatch — each step ID → correct concrete subclass (10 tests)
 *  6. of(Encoded) error paths — arity mismatch, unknown ID (5 tests)
 *  7. encode() round-trip — construct → encode → of → same subclass/step (10 tests)
 *  8. encode() layout pin — 2-element list with correct step value and parts (3 tests)
 *  9. Wire-format golden-hex pins — byte-exact output for two subclasses (2 tests)
 */
class ObvTransferStepTest {

    // ─── Reflection helpers ────────────────────────────────────────────────────

    /**
     * Invoke the package-private [ObvTransferStep.encode] method.
     * The method is accessible from the same package in Java, but Kotlin test
     * code in the same package still needs reflection because Kotlin respects
     * the package-private modifier via JVM access checks.
     */
    private val encodeMethod: Method by lazy {
        ObvTransferStep::class.java.getDeclaredMethod("encode").also { it.isAccessible = true }
    }

    private fun ObvTransferStep.encodeViaReflection(): Encoded =
        encodeMethod.invoke(this) as Encoded

    /**
     * Build the outer Encoded that [ObvTransferStep.of] expects:
     *   list [ Encoded.of(stepValue), Encoded.of(partsArray) ]
     */
    private fun buildEncoded(stepValue: Long, vararg parts: Encoded): Encoded =
        Encoded.of(
            arrayOf(
                Encoded.of(stepValue),
                Encoded.of(parts.toList().toTypedArray()),
            )
        )

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)
    }

    // ─── Group 1: Step enum integer ID wire-format pins ───────────────────────
    //
    // These integer values are encoded into persisted/transmitted bytes. Any
    // accidental renumbering during a Kotlin migration silently corrupts existing
    // data. Pin every value explicitly.

    @Test
    fun testStepValue_sourceWaitForSessionNumber_is0() {
        assertEquals(0, Step.SOURCE_WAIT_FOR_SESSION_NUMBER.value)
    }

    @Test
    fun testStepValue_sourceDisplaySessionNumber_is1() {
        assertEquals(1, Step.SOURCE_DISPLAY_SESSION_NUMBER.value)
    }

    @Test
    fun testStepValue_targetSessionNumberInput_is2() {
        assertEquals(2, Step.TARGET_SESSION_NUMBER_INPUT.value)
    }

    @Test
    fun testStepValue_ongoingProtocol_is3() {
        assertEquals(3, Step.ONGOING_PROTOCOL.value)
    }

    @Test
    fun testStepValue_sourceSasInput_is4() {
        assertEquals(4, Step.SOURCE_SAS_INPUT.value)
    }

    @Test
    fun testStepValue_targetShowSas_is5() {
        assertEquals(5, Step.TARGET_SHOW_SAS.value)
    }

    @Test
    fun testStepValue_sourceSnapshotSent_is6() {
        assertEquals(6, Step.SOURCE_SNAPSHOT_SENT.value)
    }

    @Test
    fun testStepValue_targetSnapshotReceived_is7() {
        assertEquals(7, Step.TARGET_SNAPSHOT_RECEIVED.value)
    }

    @Test
    fun testStepValue_targetRequestsKeycloakAuthenticationProof_is8() {
        assertEquals(8, Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF.value)
    }

    @Test
    fun testStepValue_fail_is1000() {
        assertEquals(1000, Step.FAIL.value)
    }

    // ─── Group 2: Step.fromIntValue mapping ───────────────────────────────────
    //
    // fromIntValue is used by of(Encoded) to decode the wire integer.
    // Each valid value must map to the exact enum constant; each unknown value
    // must return null (not throw, not return a fallback).

    @Test
    fun testFromIntValue_0_isSourceWaitForSessionNumber() {
        assertEquals(Step.SOURCE_WAIT_FOR_SESSION_NUMBER, Step.fromIntValue(0))
    }

    @Test
    fun testFromIntValue_1_isSourceDisplaySessionNumber() {
        assertEquals(Step.SOURCE_DISPLAY_SESSION_NUMBER, Step.fromIntValue(1))
    }

    @Test
    fun testFromIntValue_2_isTargetSessionNumberInput() {
        assertEquals(Step.TARGET_SESSION_NUMBER_INPUT, Step.fromIntValue(2))
    }

    @Test
    fun testFromIntValue_3_isOngoingProtocol() {
        assertEquals(Step.ONGOING_PROTOCOL, Step.fromIntValue(3))
    }

    @Test
    fun testFromIntValue_4_isSourceSasInput() {
        assertEquals(Step.SOURCE_SAS_INPUT, Step.fromIntValue(4))
    }

    @Test
    fun testFromIntValue_5_isTargetShowSas() {
        assertEquals(Step.TARGET_SHOW_SAS, Step.fromIntValue(5))
    }

    @Test
    fun testFromIntValue_6_isSourceSnapshotSent() {
        assertEquals(Step.SOURCE_SNAPSHOT_SENT, Step.fromIntValue(6))
    }

    @Test
    fun testFromIntValue_7_isTargetSnapshotReceived() {
        assertEquals(Step.TARGET_SNAPSHOT_RECEIVED, Step.fromIntValue(7))
    }

    @Test
    fun testFromIntValue_8_isTargetRequestsKeycloakAuthenticationProof() {
        assertEquals(Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF, Step.fromIntValue(8))
    }

    @Test
    fun testFromIntValue_1000_isFail() {
        assertEquals(Step.FAIL, Step.fromIntValue(1000))
    }

    @Test
    fun testFromIntValue_negative1_isNull() {
        assertNull(Step.fromIntValue(-1))
    }

    @Test
    fun testFromIntValue_9_isNull() {
        assertNull(Step.fromIntValue(9))
    }

    @Test
    fun testFromIntValue_999_isNull() {
        assertNull(Step.fromIntValue(999))
    }

    @Test
    fun testFromIntValue_1001_isNull() {
        assertNull(Step.fromIntValue(1001))
    }

    @Test
    fun testFromIntValue_intMaxValue_isNull() {
        assertNull(Step.fromIntValue(Int.MAX_VALUE))
    }

    // ─── Group 3: Fail reason constants ───────────────────────────────────────
    //
    // These ints are encoded in the Fail subclass's getEncodedParts() and sent
    // on the wire. Pin the exact values so a migration can never silently renumber them.

    @Test
    fun testFailReason_networkError_is1() {
        assertEquals(1, Fail.FAIL_REASON_NETWORK_ERROR)
    }

    @Test
    fun testFailReason_transferredIdentityAlreadyExists_is2() {
        assertEquals(2, Fail.FAIL_REASON_TRANSFERRED_IDENTITY_ALREADY_EXISTS)
    }

    @Test
    fun testFailReason_invalidResponse_is3() {
        assertEquals(3, Fail.FAIL_REASON_INVALID_RESPONSE)
    }

    @Test
    fun testFailReason_transferRestrictedAndNoOidc_is4() {
        assertEquals(4, Fail.FAIL_REASON_TRANSFER_RESTRICTED_AND_NO_OIDC)
    }

    // ─── Group 4: Step enum count ──────────────────────────────────────────────
    //
    // Pin the total number of declared enum constants. Adding or dropping a constant
    // changes the wire format — this test ensures such a change is not invisible.

    @Test
    fun testStepEnum_hasExactly10Constants() {
        assertEquals(
            "Step enum must declare exactly 10 constants (wire-format contract)",
            10,
            Step.values().size,
        )
    }

    // ─── Group 5: of(Encoded) dispatch — correct concrete subclass ────────────
    //
    // The dispatch in of() is load-bearing: each integer step value must be routed
    // to the matching concrete class. A Kotlin migration that reorders the switch
    // cases or changes a class name would break deserialization.

    @Test
    fun testOf_stepValue0_dispatchesToSourceWaitForSessionNumberStep() {
        val encoded = buildEncoded(0L)
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 0 must decode to SourceWaitForSessionNumberStep, got ${result::class.simpleName}",
            result is SourceWaitForSessionNumberStep,
        )
    }

    @Test
    fun testOf_stepValue1_dispatchesToSourceDisplaySessionNumber() {
        val encoded = buildEncoded(1L, Encoded.of(42L))
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 1 must decode to SourceDisplaySessionNumber, got ${result::class.simpleName}",
            result is SourceDisplaySessionNumber,
        )
    }

    @Test
    fun testOf_stepValue2_dispatchesToTargetSessionNumberInput() {
        val encoded = buildEncoded(2L)
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 2 must decode to TargetSessionNumberInput, got ${result::class.simpleName}",
            result is TargetSessionNumberInput,
        )
    }

    @Test
    fun testOf_stepValue3_dispatchesToOngoingProtocol() {
        val encoded = buildEncoded(3L)
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 3 must decode to OngoingProtocol, got ${result::class.simpleName}",
            result is OngoingProtocol,
        )
    }

    @Test
    fun testOf_stepValue4_dispatchesToSourceSasInput() {
        val encoded = buildEncoded(4L, Encoded.of("abc123"), Encoded.of("myDevice"))
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 4 must decode to SourceSasInput, got ${result::class.simpleName}",
            result is SourceSasInput,
        )
    }

    @Test
    fun testOf_stepValue5_dispatchesToTargetShowSas() {
        val encoded = buildEncoded(5L, Encoded.of("XY1234"))
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 5 must decode to TargetShowSas, got ${result::class.simpleName}",
            result is TargetShowSas,
        )
    }

    @Test
    fun testOf_stepValue6_dispatchesToSourceSnapshotSent() {
        val encoded = buildEncoded(6L)
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 6 must decode to SourceSnapshotSent, got ${result::class.simpleName}",
            result is SourceSnapshotSent,
        )
    }

    @Test
    fun testOf_stepValue7_dispatchesToTargetSnapshotReceived() {
        val encoded = buildEncoded(7L)
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 7 must decode to TargetSnapshotReceived, got ${result::class.simpleName}",
            result is TargetSnapshotReceived,
        )
    }

    @Test
    fun testOf_stepValue8_dispatchesToTargetRequestsKeycloakAuthenticationProof() {
        val encoded = buildEncoded(
            8L,
            Encoded.of("https://kc.example.com"),
            Encoded.of("client-id"),
            Encoded.of("AABBCCDD"),
            Encoded.of(987654321L),
        )
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 8 must decode to TargetRequestsKeycloakAuthenticationProof, got ${result::class.simpleName}",
            result is TargetRequestsKeycloakAuthenticationProof,
        )
    }

    @Test
    fun testOf_stepValue1000_dispatchesToFail() {
        val encoded = buildEncoded(1000L, Encoded.of(1L))
        val result = ObvTransferStep.of(encoded)
        assertTrue(
            "step 1000 must decode to Fail, got ${result::class.simpleName}",
            result is Fail,
        )
    }

    // ─── Group 6: of(Encoded) error paths ─────────────────────────────────────

    @Test
    fun testOf_listOf1Element_throwsDecodingException() {
        // The outer list must have exactly 2 elements; 1 element must throw.
        val tooShort = Encoded.of(arrayOf(Encoded.of(0L)))
        try {
            ObvTransferStep.of(tooShort)
            fail("Expected DecodingException for 1-element outer list")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testOf_listOf3Elements_throwsDecodingException() {
        // 3 elements must also throw.
        val tooLong = Encoded.of(
            arrayOf(
                Encoded.of(0L),
                Encoded.of(arrayOf<Encoded>()),
                Encoded.of(0L),
            )
        )
        try {
            ObvTransferStep.of(tooLong)
            fail("Expected DecodingException for 3-element outer list")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testOf_unknownStepValue_throwsDecodingException() {
        // Step ID -1 is not in the enum; fromIntValue returns null → DecodingException.
        val unknownStep = buildEncoded(-1L)
        try {
            ObvTransferStep.of(unknownStep)
            fail("Expected DecodingException for unknown step ID -1")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testOf_sourceWaitForSessionNumber_wrongPartsArity_throwsDecodingException() {
        // SourceWaitForSessionNumberStep requires exactly 0 parts; providing 1 must throw.
        val encoded = buildEncoded(0L, Encoded.of(99L))
        try {
            ObvTransferStep.of(encoded)
            fail("Expected DecodingException: SourceWaitForSessionNumberStep requires 0 parts")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testOf_sourceDisplaySessionNumber_wrongPartsArity_throwsDecodingException() {
        // SourceDisplaySessionNumber requires exactly 1 part; providing 0 must throw.
        val encoded = buildEncoded(1L)
        try {
            ObvTransferStep.of(encoded)
            fail("Expected DecodingException: SourceDisplaySessionNumber requires 1 part")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // ─── Group 7: encode() round-trip ─────────────────────────────────────────
    //
    // For each concrete subclass: construct an instance, encode it, decode it
    // via of(), and assert the result is the same subclass with the same Step enum.
    // This validates that encode() and of() are inverses for all 10 subclasses.

    @Test
    fun testRoundTrip_sourceWaitForSessionNumberStep() {
        val original = SourceWaitForSessionNumberStep()
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded)
        assertTrue(decoded is SourceWaitForSessionNumberStep)
        assertEquals(Step.SOURCE_WAIT_FOR_SESSION_NUMBER, decoded.getStep())
    }

    @Test
    fun testRoundTrip_sourceDisplaySessionNumber() {
        val original = SourceDisplaySessionNumber(123456789L)
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded) as SourceDisplaySessionNumber
        assertEquals(Step.SOURCE_DISPLAY_SESSION_NUMBER, decoded.getStep())
        assertEquals(123456789L, decoded.sessionNumber)
    }

    @Test
    fun testRoundTrip_targetSessionNumberInput() {
        val original = TargetSessionNumberInput()
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded)
        assertTrue(decoded is TargetSessionNumberInput)
        assertEquals(Step.TARGET_SESSION_NUMBER_INPUT, decoded.getStep())
    }

    @Test
    fun testRoundTrip_ongoingProtocol() {
        val original = OngoingProtocol()
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded)
        assertTrue(decoded is OngoingProtocol)
        assertEquals(Step.ONGOING_PROTOCOL, decoded.getStep())
    }

    @Test
    fun testRoundTrip_sourceSasInput() {
        val original = SourceSasInput("ABCD-1234", "Alice's Phone")
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded) as SourceSasInput
        assertEquals(Step.SOURCE_SAS_INPUT, decoded.getStep())
        assertEquals("ABCD-1234", decoded.correctSas)
        assertEquals("Alice's Phone", decoded.targetDeviceName)
    }

    @Test
    fun testRoundTrip_targetShowSas() {
        val original = TargetShowSas("9876")
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded) as TargetShowSas
        assertEquals(Step.TARGET_SHOW_SAS, decoded.getStep())
        assertEquals("9876", decoded.sas)
    }

    @Test
    fun testRoundTrip_sourceSnapshotSent() {
        val original = SourceSnapshotSent()
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded)
        assertTrue(decoded is SourceSnapshotSent)
        assertEquals(Step.SOURCE_SNAPSHOT_SENT, decoded.getStep())
    }

    @Test
    fun testRoundTrip_targetSnapshotReceived() {
        val original = TargetSnapshotReceived()
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded)
        assertTrue(decoded is TargetSnapshotReceived)
        assertEquals(Step.TARGET_SNAPSHOT_RECEIVED, decoded.getStep())
    }

    @Test
    fun testRoundTrip_targetRequestsKeycloakAuthenticationProof_withClientSecret() {
        val original = TargetRequestsKeycloakAuthenticationProof(
            "https://kc.example.com",
            "my-client-id",
            "s3cr3t",
            "AABBCCDD",
            555L,
        )
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded) as TargetRequestsKeycloakAuthenticationProof
        assertEquals(Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF, decoded.getStep())
        assertEquals("https://kc.example.com", decoded.keycloakServerUrl)
        assertEquals("my-client-id", decoded.clientId)
        assertEquals("s3cr3t", decoded.clientSecret)
        assertEquals("AABBCCDD", decoded.fullSas)
        assertEquals(555L, decoded.sessionNumber)
    }

    @Test
    fun testRoundTrip_targetRequestsKeycloakAuthenticationProof_nullClientSecret() {
        val original = TargetRequestsKeycloakAuthenticationProof(
            "https://kc.example.com",
            "my-client-id",
            null,
            "XXYYZZ",
            42L,
        )
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded) as TargetRequestsKeycloakAuthenticationProof
        assertEquals(Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF, decoded.getStep())
        assertNull(decoded.clientSecret)
        assertEquals("XXYYZZ", decoded.fullSas)
        assertEquals(42L, decoded.sessionNumber)
    }

    @Test
    fun testRoundTrip_fail_withNetworkError() {
        val original = Fail(Fail.FAIL_REASON_NETWORK_ERROR)
        val encoded = original.encodeViaReflection()
        val decoded = ObvTransferStep.of(encoded) as Fail
        assertEquals(Step.FAIL, decoded.getStep())
        assertEquals(Fail.FAIL_REASON_NETWORK_ERROR, decoded.failReason)
    }

    // ─── Group 8: encode() layout pin ─────────────────────────────────────────
    //
    // encode() must produce a 2-element Encoded list where:
    //   [0] = Encoded.of(step.value) (the step integer)
    //   [1] = Encoded.of(getEncodedParts()) (the parts list)
    // This structural contract is what of(Encoded) relies on.

    @Test
    fun testEncodeLayout_sourceWaitForSessionNumber_has2Elements() {
        val step = SourceWaitForSessionNumberStep()
        val encoded = step.encodeViaReflection()
        val list = encoded.decodeList()
        assertEquals("encode() outer list must have exactly 2 elements", 2, list.size)
    }

    @Test
    fun testEncodeLayout_firstElementIsStepValue() {
        val step = SourceWaitForSessionNumberStep()
        val encoded = step.encodeViaReflection()
        val list = encoded.decodeList()
        val decodedId = list[0].decodeLong().toInt()
        assertEquals(Step.SOURCE_WAIT_FOR_SESSION_NUMBER.value, decodedId)
    }

    @Test
    fun testEncodeLayout_secondElementIsPartsList_forFailStep() {
        val step = Fail(Fail.FAIL_REASON_INVALID_RESPONSE)
        val encoded = step.encodeViaReflection()
        val list = encoded.decodeList()
        // The step ID must be the Fail value
        assertEquals(Step.FAIL.value.toLong(), list[0].decodeLong())
        // The second element must decode to a 1-element list containing the fail reason
        val partsList = list[1].decodeList()
        assertEquals(1, partsList.size)
        assertEquals(Fail.FAIL_REASON_INVALID_RESPONSE.toLong(), partsList[0].decodeLong())
    }

    // ─── Group 9: Wire-format golden-hex pins ─────────────────────────────────
    //
    // Pin the exact byte output of encode() for two subclasses so that any
    // accidental change to the encoding format (e.g. changing INT_ENCODING_LENGTH,
    // or reordering parts) is caught immediately with a clear diff.
    //
    // Encoding anatomy for SourceWaitForSessionNumberStep (step.value = 0, 0 parts):
    //   Encoded.of(0L):
    //     [01]           — BYTE_IDS_INT
    //     [00 00 00 08]  — uint32 length = 8 (INT_ENCODING_LENGTH)
    //     [00 00 00 00 00 00 00 00]  — value 0 as big-endian 8 bytes
    //     → 13 bytes: 01 00 00 00 08 00 00 00 00 00 00 00 00
    //   Encoded.of(emptyArray):
    //     [03]           — BYTE_IDS_LIST
    //     [00 00 00 00]  — uint32 length = 0
    //     → 5 bytes: 03 00 00 00 00
    //   Outer list (13 + 5 = 18 = 0x12 bytes of content):
    //     [03]           — BYTE_IDS_LIST
    //     [00 00 00 12]  — uint32 length = 18
    //     <13 bytes>     — Encoded.of(0L)
    //     <5 bytes>      — Encoded.of(emptyArray)
    //     → 23 bytes total

    @Test
    fun testGoldenHex_sourceWaitForSessionNumberStep() {
        val step = SourceWaitForSessionNumberStep()
        val encoded = step.encodeViaReflection()
        val hex = encoded.bytes.joinToString("") { "%02x".format(it) }
        // 23 bytes:
        //   outer list header (5):    03 00 00 00 12  (content length = 18)
        //   Encoded.of(0L) (13):      01 00 00 00 08  00 00 00 00 00 00 00 00
        //   Encoded.of(emptyList)(5): 03 00 00 00 00
        assertEquals(
            "0300000012010000000800000000000000000300000000",
            hex,
        )
    }

    //
    // Encoding anatomy for Fail(FAIL_REASON_NETWORK_ERROR = 1, step.value = 1000 = 0x3E8):
    //   Encoded.of(1000L):
    //     [01 00 00 00 08]  — BYTE_IDS_INT, length = 8
    //     [00 00 00 00 00 00 03 E8]  — 1000 as big-endian 8 bytes
    //     → 13 bytes: 01 00 00 00 08 00 00 00 00 00 00 03 e8
    //   Encoded.of(1L) (the fail reason):
    //     [01 00 00 00 08]
    //     [00 00 00 00 00 00 00 01]
    //     → 13 bytes: 01 00 00 00 08 00 00 00 00 00 00 00 01
    //   Encoded.of([Encoded.of(1L)]) (the parts list, 13 bytes of content = 0x0D):
    //     [03 00 00 00 0D]  — BYTE_IDS_LIST, length = 13
    //     <13 bytes>
    //     → 18 bytes: 03 00 00 00 0d 01 00 00 00 08 00 00 00 00 00 00 00 01
    //   Outer list (13 + 18 = 31 = 0x1F bytes of content):
    //     [03 00 00 00 1F]
    //     <13 bytes Encoded.of(1000L)>
    //     <18 bytes parts list>
    //     → 36 bytes total

    @Test
    fun testGoldenHex_failWithNetworkError() {
        val step = Fail(Fail.FAIL_REASON_NETWORK_ERROR)
        val encoded = step.encodeViaReflection()
        val hex = encoded.bytes.joinToString("") { "%02x".format(it) }
        // 36 bytes:
        //   outer list header (5):  03 00 00 00 1f  (content = 13+18 = 31 = 0x1f)
        //   Encoded.of(1000L) (13): 01 00 00 00 08  00 00 00 00 00 00 03 e8
        //   parts list header (5):  03 00 00 00 0d  (content = 13 = 0x0d)
        //   Encoded.of(1L) (13):    01 00 00 00 08  00 00 00 00 00 00 00 01
        assertEquals(
            "030000001f" +
                "010000000800000000000003e8" +
                "030000000d" +
                "01000000080000000000000001",
            hex,
        )
    }
}
