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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.DialogType
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.UUID

/**
 * Characterization tests for [GenericProtocolMessageToSend].
 *
 * The class is a thin DTO whose entire behavioral surface is its three
 * `generateChannelXxxMessageToSend()` dispatch methods and the private
 * `encode()` wire-format helper. These tests pin the channel-type dispatch
 * contract so that a Java→Kotlin migration that silently drops or reorders
 * a `when` branch is caught immediately.
 *
 * ## Groups
 * 1. `generateChannelProtocolMessageToSend()` — 9 dispatch tests + 3 field-origin tests
 * 2. `generateChannelDialogMessageToSend()` — 9 dispatch tests + 4 field-origin tests
 * 3. `generateChannelServerQueryMessageToSend()` — 9 dispatch tests + 3 field-origin tests
 * 4. `encode()` wire-format layout — 4 element-level tests
 * 5. Wire-format value pin — 1 golden-hex test
 * 6. `hasUserContent` stored verbatim — 2 tests
 */
class GenericProtocolMessageToSendTest {

    // ─── Shared fixtures ──────────────────────────────────────────────────────

    private lateinit var identity: Identity
    private lateinit var identity2: Identity
    private lateinit var uid: UID

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

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair1 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair1 = EncryptionEciesCurve25519KeyPair.generate(prng)
        identity = Identity(
            "test.olvid.io",
            serverAuthKeyPair1.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair1.publicKey as EncryptionPublicKey,
        )

        val serverAuthKeyPair2 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair2 = EncryptionEciesCurve25519KeyPair.generate(prng)
        identity2 = Identity(
            "test.olvid.io",
            serverAuthKeyPair2.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair2.publicKey as EncryptionPublicKey,
        )

        uid = UID(prng)
    }

    // ─── Convenience builders ─────────────────────────────────────────────────

    private fun makeMsg(
        sendChannelInfo: SendChannelInfo,
        protocolId: Int = 1,
        protocolInstanceUid: UID = uid,
        protocolMessageId: Int = 2,
        inputs: Array<Encoded> = arrayOf(),
        hasUserContent: Boolean = false,
    ): GenericProtocolMessageToSend =
        GenericProtocolMessageToSend(
            sendChannelInfo,
            protocolId,
            protocolInstanceUid,
            protocolMessageId,
            inputs,
            hasUserContent,
        )

    /** Read the private `encodedElements` field via reflection. */
    private fun encodedElements(msg: GenericProtocolMessageToSend): Encoded {
        val f = GenericProtocolMessageToSend::class.java.getDeclaredField("encodedElements")
        f.isAccessible = true
        return f.get(msg) as Encoded
    }

    // ─── SendChannelInfo factories for each channel type ─────────────────────

    private fun localInfo(): SendChannelInfo =
        SendChannelInfo.createLocalChannelInfo(identity)!!

    private fun obliviousChannelInfo(): SendChannelInfo =
        SendChannelInfo.createObliviousChannelInfo(
            identity2,
            identity,
            arrayOf<UID?>(uid),
            true,
        )!!

    private fun asymmetricChannelInfo(): SendChannelInfo =
        SendChannelInfo.createAsymmetricChannelInfo(
            identity2,
            identity,
            arrayOf<UID?>(uid),
        )!!

    private fun allConfirmedObliviousOrPreKeyInfo(): SendChannelInfo =
        SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfo(identity2, identity)!!

    private fun asymmetricBroadcastChannelInfo(): SendChannelInfo =
        SendChannelInfo.createAsymmetricBroadcastChannelInfo(identity2, identity)!!

    private fun allOwnedConfirmedObliviousOrPreKeyInfo(): SendChannelInfo =
        SendChannelInfo.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(identity)!!

    private fun obliviousChannelOrPreKeyInfo(): SendChannelInfo =
        SendChannelInfo.createObliviousChannelOrPreKeyInfo(
            identity2,
            identity,
            arrayOf<UID?>(uid),
            true,
        )!!

    private fun userInterfaceInfo(): SendChannelInfo =
        SendChannelInfo.createUserInterfaceChannelInfo(
            identity,
            DialogType.createDeleteDialog(),
            UUID.randomUUID(),
        )!!

    private fun serverQueryInfo(): SendChannelInfo =
        SendChannelInfo.createServerQueryChannelInfo(
            identity,
            ServerQuery.DeviceDiscoveryQuery(identity),
        )!!

    // ─── Group 1: generateChannelProtocolMessageToSend() dispatch ─────────────

    @Test
    fun testGenerateProtocol_localType_returnsNonNull() {
        val msg = makeMsg(localInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_obliviousChannelType_returnsNonNull() {
        val msg = makeMsg(obliviousChannelInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_asymmetricChannelType_returnsNonNull() {
        val msg = makeMsg(asymmetricChannelInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_allConfirmedObliviousOrPreKeyType_returnsNonNull() {
        val msg = makeMsg(allConfirmedObliviousOrPreKeyInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_asymmetricBroadcastChannelType_returnsNonNull() {
        val msg = makeMsg(asymmetricBroadcastChannelInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_allOwnedConfirmedObliviousOrPreKeyType_returnsNonNull() {
        val msg = makeMsg(allOwnedConfirmedObliviousOrPreKeyInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_obliviousChannelOrPreKeyType_returnsNonNull() {
        val msg = makeMsg(obliviousChannelOrPreKeyInfo())
        assertNotNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_userInterfaceType_returnsNull() {
        val msg = makeMsg(userInterfaceInfo())
        assertNull(msg.generateChannelProtocolMessageToSend())
    }

    @Test
    fun testGenerateProtocol_serverQueryType_returnsNull() {
        val msg = makeMsg(serverQueryInfo())
        assertNull(msg.generateChannelProtocolMessageToSend())
    }

    // Pin that the returned ChannelProtocolMessageToSend carries the source instance's fields.

    @Test
    fun testGenerateProtocol_sendChannelInfo_comesFromSourceInstance() {
        val info = localInfo()
        val msg = makeMsg(info)
        val result = msg.generateChannelProtocolMessageToSend()!!
        // The source passes `sendChannelInfo` directly to the ChannelProtocolMessageToSend
        // constructor — verify by reference identity.
        assertSame(info, result.sendChannelInfo)
    }

    @Test
    fun testGenerateProtocol_messagePayload_equalsEncodedElements() {
        val msg = makeMsg(localInfo())
        val result = msg.generateChannelProtocolMessageToSend()!!
        // encodedElements in ChannelProtocolMessageToSend must match the private
        // field on GenericProtocolMessageToSend (same object reference, since it's
        // passed directly without copying).
        assertSame(encodedElements(msg), result.encodedElements)
    }

    @Test
    fun testGenerateProtocol_hasUserContent_comesFromSourceInstance() {
        // Verify with both true and false to prevent a hard-coded constant from sneaking in.
        val msgTrue = makeMsg(localInfo(), hasUserContent = true)
        assertTrue(msgTrue.generateChannelProtocolMessageToSend()!!.hasUserContent())

        val msgFalse = makeMsg(localInfo(), hasUserContent = false)
        assertTrue(!msgFalse.generateChannelProtocolMessageToSend()!!.hasUserContent())
    }

    // ─── Group 2: generateChannelDialogMessageToSend() dispatch ──────────────

    @Test
    fun testGenerateDialog_userInterfaceType_returnsNonNull() {
        val msg = makeMsg(userInterfaceInfo())
        assertNotNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_localType_returnsNull() {
        val msg = makeMsg(localInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_obliviousChannelType_returnsNull() {
        val msg = makeMsg(obliviousChannelInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_asymmetricChannelType_returnsNull() {
        val msg = makeMsg(asymmetricChannelInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_allConfirmedObliviousOrPreKeyType_returnsNull() {
        val msg = makeMsg(allConfirmedObliviousOrPreKeyInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_asymmetricBroadcastChannelType_returnsNull() {
        val msg = makeMsg(asymmetricBroadcastChannelInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_allOwnedConfirmedObliviousOrPreKeyType_returnsNull() {
        val msg = makeMsg(allOwnedConfirmedObliviousOrPreKeyInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_obliviousChannelOrPreKeyType_returnsNull() {
        val msg = makeMsg(obliviousChannelOrPreKeyInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    @Test
    fun testGenerateDialog_serverQueryType_returnsNull() {
        val msg = makeMsg(serverQueryInfo())
        assertNull(msg.generateChannelDialogMessageToSend())
    }

    // Pin that ChannelDialogMessageToSend is constructed with the source sendChannelInfo fields.

    @Test
    fun testGenerateDialog_dialogUuid_comesFromSendChannelInfo() {
        val uuid = UUID.randomUUID()
        val info = SendChannelInfo.createUserInterfaceChannelInfo(
            identity,
            DialogType.createDeleteDialog(),
            uuid,
        )!!
        val msg = makeMsg(info)
        val result = msg.generateChannelDialogMessageToSend()!!
        assertEquals(uuid, result.uuid)
    }

    @Test
    fun testGenerateDialog_toIdentity_comesFromSendChannelInfo() {
        val uuid = UUID.randomUUID()
        val info = SendChannelInfo.createUserInterfaceChannelInfo(
            identity,
            DialogType.createDeleteDialog(),
            uuid,
        )!!
        val msg = makeMsg(info)
        val result = msg.generateChannelDialogMessageToSend()!!
        // The ChannelDialogMessageToSend re-creates a SendChannelInfo internally;
        // verify that the toIdentity threaded through matches the source.
        assertArrayEquals(identity.getBytes(), result.sendChannelInfo?.toIdentity?.getBytes())
    }

    @Test
    fun testGenerateDialog_dialogType_comesFromSendChannelInfo() {
        val uuid = UUID.randomUUID()
        val dialogType = DialogType.createDeleteDialog()
        val info = SendChannelInfo.createUserInterfaceChannelInfo(
            identity,
            dialogType,
            uuid,
        )!!
        val msg = makeMsg(info)
        val result = msg.generateChannelDialogMessageToSend()!!
        // DialogType does not override equals; check the id field instead.
        assertEquals(DialogType.DELETE_DIALOG_ID, result.sendChannelInfo?.dialogType?.id)
    }

    @Test
    fun testGenerateDialog_encodedElements_comesFromSourceInstance() {
        val info = userInterfaceInfo()
        val msg = makeMsg(info)
        val result = msg.generateChannelDialogMessageToSend()!!
        assertSame(encodedElements(msg), result.encodedElements)
    }

    // ─── Group 3: generateChannelServerQueryMessageToSend() dispatch ──────────

    @Test
    fun testGenerateServerQuery_serverQueryType_returnsNonNull() {
        val msg = makeMsg(serverQueryInfo())
        assertNotNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_localType_returnsNull() {
        val msg = makeMsg(localInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_obliviousChannelType_returnsNull() {
        val msg = makeMsg(obliviousChannelInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_asymmetricChannelType_returnsNull() {
        val msg = makeMsg(asymmetricChannelInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_allConfirmedObliviousOrPreKeyType_returnsNull() {
        val msg = makeMsg(allConfirmedObliviousOrPreKeyInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_asymmetricBroadcastChannelType_returnsNull() {
        val msg = makeMsg(asymmetricBroadcastChannelInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_allOwnedConfirmedObliviousOrPreKeyType_returnsNull() {
        val msg = makeMsg(allOwnedConfirmedObliviousOrPreKeyInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_obliviousChannelOrPreKeyType_returnsNull() {
        val msg = makeMsg(obliviousChannelOrPreKeyInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    @Test
    fun testGenerateServerQuery_userInterfaceType_returnsNull() {
        val msg = makeMsg(userInterfaceInfo())
        assertNull(msg.generateChannelServerQueryMessageToSend())
    }

    // Pin that ChannelServerQueryMessageToSend carries the source sendChannelInfo fields.

    @Test
    fun testGenerateServerQuery_toIdentity_comesFromSendChannelInfo() {
        val info = serverQueryInfo()
        val msg = makeMsg(info)
        val result = msg.generateChannelServerQueryMessageToSend()!!
        assertArrayEquals(identity.getBytes(), result.sendChannelInfo?.toIdentity?.getBytes())
    }

    @Test
    fun testGenerateServerQuery_serverQueryType_comesFromSendChannelInfo() {
        val queryType = ServerQuery.DeviceDiscoveryQuery(identity)
        val info = SendChannelInfo.createServerQueryChannelInfo(identity, queryType)!!
        val msg = makeMsg(info)
        val result = msg.generateChannelServerQueryMessageToSend()!!
        // The TypeId is the wire-contract discriminator; check it did not get swapped.
        assertEquals(
            ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID,
            result.sendChannelInfo?.serverQueryType?.id,
        )
    }

    @Test
    fun testGenerateServerQuery_encodedElements_comesFromSourceInstance() {
        val info = serverQueryInfo()
        val msg = makeMsg(info)
        val result = msg.generateChannelServerQueryMessageToSend()!!
        assertSame(encodedElements(msg), result.encodedElements)
    }

    // ─── Group 4: encode() wire-format layout (via private-field access) ──────
    //
    // The `encode()` method produces:
    //   Encoded.of([encoded(protocolId), encoded(protocolInstanceUid),
    //               encoded(protocolMessageId), encoded(inputs)])
    // Pinning each element independently catches any reordering or substitution.

    private fun buildEncodedElements(
        protocolId: Int,
        protocolInstanceUid: UID,
        protocolMessageId: Int,
        inputs: Array<Encoded>,
    ): Encoded {
        val msg = GenericProtocolMessageToSend(
            localInfo(), protocolId, protocolInstanceUid, protocolMessageId, inputs, false,
        )
        return encodedElements(msg)
    }

    @Test
    fun testEncodeLayout_outerListHasFourElements() {
        val encoded = buildEncodedElements(1, uid, 2, arrayOf())
        val list = encoded.decodeList()
        assertEquals("outer list must have exactly 4 elements", 4, list.size)
    }

    @Test
    fun testEncodeLayout_element0_isProtocolId() {
        val protocolId = 99
        val encoded = buildEncodedElements(protocolId, uid, 2, arrayOf())
        val element0 = encoded.decodeList()[0]
        assertEquals(
            "element[0] must decode to the protocol id",
            protocolId.toLong(),
            element0.decodeLong(),
        )
    }

    @Test
    fun testEncodeLayout_element1_isProtocolInstanceUid() {
        val zeroUid = UID(ByteArray(32))
        val encoded = buildEncodedElements(1, zeroUid, 2, arrayOf())
        val element1 = encoded.decodeList()[1]
        assertArrayEquals(
            "element[1] must decode to the protocolInstanceUid bytes",
            zeroUid.bytes,
            element1.decodeUid().bytes,
        )
    }

    @Test
    fun testEncodeLayout_element2_isProtocolMessageId() {
        val protocolMessageId = 77
        val encoded = buildEncodedElements(1, uid, protocolMessageId, arrayOf())
        val element2 = encoded.decodeList()[2]
        assertEquals(
            "element[2] must decode to the protocol message id",
            protocolMessageId.toLong(),
            element2.decodeLong(),
        )
    }

    @Test
    fun testEncodeLayout_element3_isInputsList() {
        val input0 = Encoded.of(42L)
        val input1 = Encoded.of(ByteArray(4) { it.toByte() })
        val inputs = arrayOf(input0, input1)
        val encoded = buildEncodedElements(1, uid, 2, inputs)
        val element3List = encoded.decodeList()[3].decodeList()
        assertEquals("element[3] must have same length as inputs array", inputs.size, element3List.size)
        assertArrayEquals(
            "element[3][0] bytes must match input[0]",
            inputs[0].bytes,
            element3List[0].bytes,
        )
        assertArrayEquals(
            "element[3][1] bytes must match input[1]",
            inputs[1].bytes,
            element3List[1].bytes,
        )
    }

    // ─── Group 5: wire-format value pin (golden hex) ──────────────────────────
    //
    // Constructed with fixed inputs: protocolId=42, protocolInstanceUid=all-zero,
    // protocolMessageId=7, inputs=[].
    //
    // To regenerate: decode the hex and verify the layout using Group 4 tests.
    // Any change to the encoding scheme will break this test immediately.

    @Test
    fun testWireFormatGoldenHex() {
        val protocolId = 42
        val protocolInstanceUid = UID(ByteArray(32))
        val protocolMessageId = 7
        val inputs = arrayOf<Encoded>()

        val encoded = buildEncodedElements(protocolId, protocolInstanceUid, protocolMessageId, inputs)

        val expectedHex = "03000000440100000008000000000000002a00000000200000000000000000000000000000000000000000000000000000000000000000010000000800000000000000070300000000"
        val actualHex = encoded.bytes.joinToString("") { "%02x".format(it) }
        assertEquals(
            "Wire-format bytes must match the golden hex literal. " +
                "A change here means the encoding scheme changed.",
            expectedHex,
            actualHex,
        )
    }

    // ─── Group 6: hasUserContent stored verbatim ──────────────────────────────

    @Test
    fun testHasUserContent_trueStoredVerbatim() {
        val msg = makeMsg(localInfo(), hasUserContent = true)
        val result = msg.generateChannelProtocolMessageToSend()!!
        assertTrue(result.hasUserContent())
    }

    @Test
    fun testHasUserContent_falseStoredVerbatim() {
        val msg = makeMsg(localInfo(), hasUserContent = false)
        val result = msg.generateChannelProtocolMessageToSend()!!
        assertTrue(!result.hasUserContent())
    }
}
