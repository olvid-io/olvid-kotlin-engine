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

package io.olvid.engine.protocol.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [ChildToParentProtocolMessageInputs].
 *
 * This class is a wire-format DTO that encodes/decodes a 3-element [Encoded] array used
 * for inter-protocol communication (child → parent). A Kotlin migration that changes the
 * encoding layout or element order would silently break cross-protocol messaging.
 *
 * Test groups:
 *  1. Encode-decode roundtrip via toEncodedInputs() + Encoded[] constructor.
 *  2. Layout pin — toEncodedInputs() element positions and pass-through semantics.
 *  3. Constructor (UID, ConcreteProtocolState) — field initialization.
 *  4. Constructor (Encoded[]) — arity validation.
 *  5. Wire-format value pin — byte-exact hex literal for the all-zeros / InitialProtocolState case.
 *  6. Getters — explicit accessor delegation.
 *
 * [InitialProtocolState] is used as the concrete state because it is the simplest subclass
 * (no fields, no-arg constructor, id == 0, encode() returns an empty list).
 * A local [TestState] subclass with id == 99 is used in cases where a non-zero state id is
 * needed to make the assertion meaningful.
 */
class ChildToParentProtocolMessageInputsTest {

    // ─── Test state double ─────────────────────────────────────────────────────

    private class TestState : ConcreteProtocolState(STATE_ID) {
        override fun encode(): Encoded = Encoded.of(byteArrayOf(0x42))

        companion object {
            const val STATE_ID = 99
        }
    }

    // ─── Fixtures ──────────────────────────────────────────────────────────────

    private lateinit var zeroUid: UID
    private lateinit var initialState: InitialProtocolState
    private lateinit var testState: TestState

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

        zeroUid = UID(ByteArray(UID.UID_LENGTH))
        initialState = InitialProtocolState()
        testState = TestState()
    }

    // ─── 1. Encode-decode roundtrip ────────────────────────────────────────────

    @Test
    fun testRoundtrip_childProtocolInstanceUid() {
        val original = ChildToParentProtocolMessageInputs(zeroUid, initialState)
        val decoded = ChildToParentProtocolMessageInputs(original.toEncodedInputs())

        assertArrayEquals(
            "childProtocolInstanceUid bytes must survive encode-decode roundtrip",
            zeroUid.bytes,
            decoded.childProtocolInstanceUid.bytes
        )
    }

    @Test
    fun testRoundtrip_childProtocolReachedStateId() {
        val original = ChildToParentProtocolMessageInputs(zeroUid, testState)
        val decoded = ChildToParentProtocolMessageInputs(original.toEncodedInputs())

        assertEquals(
            "childProtocolReachedStateId must survive encode-decode roundtrip",
            TestState.STATE_ID,
            decoded.childProtocolReachedStateId
        )
    }

    @Test
    fun testRoundtrip_childProtocolEncodedState() {
        val original = ChildToParentProtocolMessageInputs(zeroUid, testState)
        val decoded = ChildToParentProtocolMessageInputs(original.toEncodedInputs())

        assertArrayEquals(
            "childProtocolEncodedState bytes must survive encode-decode roundtrip",
            testState.encode().bytes,
            decoded.childProtocolEncodedState!!.bytes
        )
    }

    @Test
    fun testRoundtrip_combined() {
        val original = ChildToParentProtocolMessageInputs(zeroUid, testState)
        val encoded = original.toEncodedInputs()
        val decoded = ChildToParentProtocolMessageInputs(encoded)

        assertArrayEquals(
            "uid bytes must match after full roundtrip",
            zeroUid.bytes,
            decoded.childProtocolInstanceUid.bytes
        )
        assertEquals(
            "stateId must match after full roundtrip",
            TestState.STATE_ID,
            decoded.childProtocolReachedStateId
        )
        assertArrayEquals(
            "encodedState bytes must match after full roundtrip",
            testState.encode().bytes,
            decoded.childProtocolEncodedState!!.bytes
        )
    }

    // ─── 2. Layout pin — toEncodedInputs() element positions ──────────────────

    @Test
    fun testToEncodedInputs_returnsExactlyThreeElements() {
        val inputs = ChildToParentProtocolMessageInputs(zeroUid, testState).toEncodedInputs()

        assertEquals(
            "toEncodedInputs() must return exactly 3 elements",
            3,
            inputs.size
        )
    }

    @Test
    fun testToEncodedInputs_element0IsEncodedUid() {
        val inputs = ChildToParentProtocolMessageInputs(zeroUid, testState).toEncodedInputs()
        val decodedUid = inputs[0].decodeUid()

        assertArrayEquals(
            "inputs[0] must decode to the original UID",
            zeroUid.bytes,
            decodedUid.bytes
        )
    }

    @Test
    fun testToEncodedInputs_element1IsEncodedStateId() {
        val inputs = ChildToParentProtocolMessageInputs(zeroUid, testState).toEncodedInputs()
        val decodedStateId = inputs[1].decodeLong().toInt()

        assertEquals(
            "inputs[1] must decode to the state id",
            TestState.STATE_ID,
            decodedStateId
        )
    }

    @Test
    fun testToEncodedInputs_element2IsPassThroughEncodedState() {
        // The encoded state must be passed through AS-IS (same object reference),
        // not re-wrapped in another layer of encoding.
        val instance = ChildToParentProtocolMessageInputs(zeroUid, testState)
        val storedEncodedState = instance.childProtocolEncodedState
        val inputs = instance.toEncodedInputs()

        assertSame(
            "inputs[2] must be the exact same Encoded reference stored in the object",
            storedEncodedState,
            inputs[2]
        )
    }

    // ─── 3. Constructor (UID, ConcreteProtocolState) — field initialization ────

    @Test
    fun testStateConstructor_storesStateId() {
        val instance = ChildToParentProtocolMessageInputs(zeroUid, testState)

        assertEquals(
            "childProtocolReachedStateId must equal state.id",
            TestState.STATE_ID,
            instance.childProtocolReachedStateId
        )
    }

    @Test
    fun testStateConstructor_encodedStateIsExactReferenceFromStateEncode() {
        // state.encode() is called once during construction; the result must be stored
        // as-is — not re-encoded, not cloned.
        val capturedEncoded = testState.encode()

        // Verify by byte equality (reference identity not guaranteed across two encode() calls
        // for this particular test double, but bytes must match the one captured above).
        val instance = ChildToParentProtocolMessageInputs(zeroUid, testState)

        assertArrayEquals(
            "childProtocolEncodedState bytes must equal the bytes returned by state.encode()",
            capturedEncoded.bytes,
            instance.childProtocolEncodedState!!.bytes
        )
    }

    // ─── 4. Constructor (Encoded[]) — arity validation ────────────────────────

    @Test(expected = Exception::class)
    fun testEncodedArrayConstructor_throwsOnEmptyArray() {
        ChildToParentProtocolMessageInputs(emptyArray())
    }

    @Test(expected = Exception::class)
    fun testEncodedArrayConstructor_throwsOnOneElement() {
        val encodedUid = Encoded.of(zeroUid)
        ChildToParentProtocolMessageInputs(arrayOf(encodedUid))
    }

    @Test(expected = Exception::class)
    fun testEncodedArrayConstructor_throwsOnTwoElements() {
        val encodedUid = Encoded.of(zeroUid)
        val encodedStateId = Encoded.of(0L)
        ChildToParentProtocolMessageInputs(arrayOf(encodedUid, encodedStateId))
    }

    @Test(expected = Exception::class)
    fun testEncodedArrayConstructor_throwsOnFourElements() {
        val encodedUid = Encoded.of(zeroUid)
        val encodedStateId = Encoded.of(0L)
        val encodedState = initialState.encode()
        val extra = Encoded.of(byteArrayOf(0x00))
        ChildToParentProtocolMessageInputs(arrayOf(encodedUid, encodedStateId, encodedState, extra))
    }

    // ─── 5. Wire-format value pin ──────────────────────────────────────────────

    /**
     * Pins the exact bytes produced by toEncodedInputs() for the all-zeros UID and
     * [InitialProtocolState] (id = 0, encode() = empty list).
     *
     * Layout:
     *   inputs[0] = Encoded.of(UID(ByteArray(32)))
     *             = 0x00 ++ 0x00000020 ++ 32×0x00   (37 bytes)
     *   inputs[1] = Encoded.of(0L)                  (INITIAL_STATE_ID = 0)
     *             = 0x01 ++ 0x00000008 ++ 8×0x00    (13 bytes)
     *   inputs[2] = InitialProtocolState.encode()   = Encoded.of(Encoded[0])
     *             = 0x03 ++ 0x00000000              ( 5 bytes)
     *
     * Concatenated wire hex (55 bytes):
     *   00000000200000000000000000000000000000000000000000000000000000000000000000
     *   010000000800000000000000000300000000
     *
     * DO NOT change this literal unless the encoding format is intentionally changed
     * and the protocol team approves.
     */
    @Test
    fun testWireFormatPin() {
        val instance = ChildToParentProtocolMessageInputs(zeroUid, initialState)
        val inputs = instance.toEncodedInputs()

        val allBytes = inputs[0].bytes + inputs[1].bytes + inputs[2].bytes
        val actualHex = allBytes.joinToString("") { "%02x".format(it) }

        val expectedHex =
            "00000000200000000000000000000000000000000000000000000000000000000000000000" +
            "010000000800000000000000000300000000"

        assertEquals(
            "Wire-format bytes must match the pinned literal — a change here means the " +
            "inter-protocol encoding layout has changed and may break child→parent messaging",
            expectedHex,
            actualHex
        )
    }

    // ─── 6. Getters ────────────────────────────────────────────────────────────

    @Test
    fun testGetChildProtocolInstanceUid() {
        val instance = ChildToParentProtocolMessageInputs(zeroUid, testState)

        assertArrayEquals(
            "getChildProtocolInstanceUid() must return the UID passed to the constructor",
            zeroUid.bytes,
            instance.childProtocolInstanceUid.bytes
        )
    }

    @Test
    fun testGetChildProtocolReachedStateId() {
        val instance = ChildToParentProtocolMessageInputs(zeroUid, testState)

        assertEquals(
            "getChildProtocolReachedStateId() must return state.id",
            TestState.STATE_ID,
            instance.childProtocolReachedStateId
        )
    }

    @Test
    fun testGetChildProtocolEncodedState() {
        val instance = ChildToParentProtocolMessageInputs(zeroUid, testState)

        assertArrayEquals(
            "getChildProtocolEncodedState() must return bytes equal to state.encode()",
            testState.encode().bytes,
            instance.childProtocolEncodedState!!.bytes
        )
    }
}
