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

package io.olvid.engine.datatypes.containers

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.DecodingException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class ReceptionChannelInfoTest {

    private lateinit var remoteDeviceUid: UID
    private lateinit var remoteIdentity: Identity

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

        remoteDeviceUid = UID(prng)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        remoteIdentity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )
    }

    // -----------------------------------------------------------------------
    // Type constant values
    // -----------------------------------------------------------------------

    @Test
    fun testTypeConstantValues() {
        assertEquals(0, ReceptionChannelInfo.LOCAL_TYPE)
        assertEquals(1, ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE)
        assertEquals(2, ReceptionChannelInfo.ASYMMETRIC_CHANNEL_TYPE)
        assertEquals(5, ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE)
        assertEquals(3, ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_OR_PRE_KEY_WITH_OWNED_DEVICE_TYPE)
        assertEquals(4, ReceptionChannelInfo.ANY_OBLIVIOUS_OR_PRE_KEY_CHANNEL_TYPE)
        assertEquals(6, ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_TYPE)
    }

    // -----------------------------------------------------------------------
    // Factory methods — channel type
    // -----------------------------------------------------------------------

    @Test
    fun testCreateLocalChannelInfo() {
        val info = ReceptionChannelInfo.createLocalChannelInfo()
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.LOCAL_TYPE, info.channelType)
        assertNull(info.remoteDeviceUid)
        assertNull(info.remoteIdentity)
    }

    @Test
    fun testCreateObliviousChannelInfo() {
        val info = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE, info.channelType)
        assertEquals(remoteDeviceUid, info.remoteDeviceUid)
        assertEquals(remoteIdentity, info.remoteIdentity)
    }

    @Test
    fun testCreateAsymmetricChannelInfo() {
        val info = ReceptionChannelInfo.createAsymmetricChannelInfo()
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.ASYMMETRIC_CHANNEL_TYPE, info.channelType)
        assertNull(info.remoteDeviceUid)
        assertNull(info.remoteIdentity)
    }

    @Test
    fun testCreatePreKeyChannelInfo() {
        val info = ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE, info.channelType)
        assertEquals(remoteDeviceUid, info.remoteDeviceUid)
        assertEquals(remoteIdentity, info.remoteIdentity)
    }

    @Test
    fun testCreateAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo() {
        val info = ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo()
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_OR_PRE_KEY_WITH_OWNED_DEVICE_TYPE, info.channelType)
        assertNull(info.remoteDeviceUid)
        assertNull(info.remoteIdentity)
    }

    @Test
    fun testCreateAnyObliviousChannelOrPreKeyInfo() {
        val info = ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyInfo()
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.ANY_OBLIVIOUS_OR_PRE_KEY_CHANNEL_TYPE, info.channelType)
        assertNull(info.remoteDeviceUid)
        assertNull(info.remoteIdentity)
    }

    @Test
    fun testCreateAnyObliviousChannelInfo() {
        val info = ReceptionChannelInfo.createAnyObliviousChannelInfo()
        assertNotNull(info)
        assertEquals(ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_TYPE, info.channelType)
        assertNull(info.remoteDeviceUid)
        assertNull(info.remoteIdentity)
    }

    // -----------------------------------------------------------------------
    // Encoded round-trip: encode() → of()
    // -----------------------------------------------------------------------

    @Test
    fun testEncodeDecodeRoundTripLocal() {
        val original = ReceptionChannelInfo.createLocalChannelInfo()
        val encoded = original.encode()
        val decoded = ReceptionChannelInfo.of(encoded)
        assertEquals(original, decoded)
        assertEquals(ReceptionChannelInfo.LOCAL_TYPE, decoded.channelType)
        assertNull(decoded.remoteDeviceUid)
        assertNull(decoded.remoteIdentity)
    }

    @Test
    fun testEncodeDecodeRoundTripOblivious() {
        val original = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        val encoded = original.encode()
        val decoded = ReceptionChannelInfo.of(encoded)
        assertEquals(original, decoded)
        assertEquals(ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE, decoded.channelType)
        assertArrayEquals(remoteDeviceUid.bytes, decoded.remoteDeviceUid!!.bytes)
        assertEquals(remoteIdentity, decoded.remoteIdentity)
    }

    @Test
    fun testEncodeDecodeRoundTripAsymmetric() {
        val original = ReceptionChannelInfo.createAsymmetricChannelInfo()
        val encoded = original.encode()
        val decoded = ReceptionChannelInfo.of(encoded)
        assertEquals(original, decoded)
        assertEquals(ReceptionChannelInfo.ASYMMETRIC_CHANNEL_TYPE, decoded.channelType)
        assertNull(decoded.remoteDeviceUid)
        assertNull(decoded.remoteIdentity)
    }

    @Test
    fun testEncodeDecodeRoundTripPreKey() {
        val original = ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)
        val encoded = original.encode()
        val decoded = ReceptionChannelInfo.of(encoded)
        assertEquals(original, decoded)
        assertEquals(ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE, decoded.channelType)
        assertArrayEquals(remoteDeviceUid.bytes, decoded.remoteDeviceUid!!.bytes)
        assertEquals(remoteIdentity, decoded.remoteIdentity)
    }

    // -----------------------------------------------------------------------
    // of() decoding failure cases
    // -----------------------------------------------------------------------

    @Test
    fun testDecodeEmptyListThrows() {
        // An encoded empty list should throw DecodingException
        val emptyListEncoded = io.olvid.engine.encoder.Encoded.of(emptyArray<io.olvid.engine.encoder.Encoded>())
        try {
            ReceptionChannelInfo.of(emptyListEncoded)
            fail("Expected DecodingException for empty list")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeLocalWithExtraElementThrows() {
        // LOCAL_TYPE must have exactly 1 element — inject an extra element
        val entries = arrayOf(
            io.olvid.engine.encoder.Encoded.of(ReceptionChannelInfo.LOCAL_TYPE.toLong()),
            io.olvid.engine.encoder.Encoded.of(42L) // extra
        )
        val bad = io.olvid.engine.encoder.Encoded.of(entries)
        try {
            ReceptionChannelInfo.of(bad)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeAsymmetricWithExtraElementThrows() {
        // ASYMMETRIC_CHANNEL_TYPE must have exactly 1 element
        val entries = arrayOf(
            io.olvid.engine.encoder.Encoded.of(ReceptionChannelInfo.ASYMMETRIC_CHANNEL_TYPE.toLong()),
            io.olvid.engine.encoder.Encoded.of(99L) // extra
        )
        val bad = io.olvid.engine.encoder.Encoded.of(entries)
        try {
            ReceptionChannelInfo.of(bad)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeObliviousWithWrongElementCountThrows() {
        // OBLIVIOUS_CHANNEL_TYPE requires 3 or 4 elements; supply only 2
        val entries = arrayOf(
            io.olvid.engine.encoder.Encoded.of(ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE.toLong()),
            io.olvid.engine.encoder.Encoded.of(remoteDeviceUid) // only uid, missing identity
        )
        val bad = io.olvid.engine.encoder.Encoded.of(entries)
        try {
            ReceptionChannelInfo.of(bad)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodePreKeyWithWrongElementCountThrows() {
        // PRE_KEY_CHANNEL_TYPE requires exactly 3 elements; supply only 2
        val entries = arrayOf(
            io.olvid.engine.encoder.Encoded.of(ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE.toLong()),
            io.olvid.engine.encoder.Encoded.of(remoteDeviceUid) // only uid, missing identity
        )
        val bad = io.olvid.engine.encoder.Encoded.of(entries)
        try {
            ReceptionChannelInfo.of(bad)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeUnknownTypeThrows() {
        // ANY_OBLIVIOUS_CHANNEL_TYPE (6) is a dummy type and is never serialised →
        // of() must reject it with DecodingException
        val entries = arrayOf(
            io.olvid.engine.encoder.Encoded.of(ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_TYPE.toLong())
        )
        val bad = io.olvid.engine.encoder.Encoded.of(entries)
        try {
            ReceptionChannelInfo.of(bad)
            fail("Expected DecodingException for dummy/unserialisable type")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // -----------------------------------------------------------------------
    // equals / hashCode
    // -----------------------------------------------------------------------

    @Test
    fun testEqualsReflexive() {
        val info = ReceptionChannelInfo.createLocalChannelInfo()
        assertEquals(info, info)
    }

    @Test
    fun testEqualsForSimpleTypes() {
        // Two independently created local-channel infos must be equal
        assertEquals(
            ReceptionChannelInfo.createLocalChannelInfo(),
            ReceptionChannelInfo.createLocalChannelInfo()
        )
        // Two asymmetric infos must be equal
        assertEquals(
            ReceptionChannelInfo.createAsymmetricChannelInfo(),
            ReceptionChannelInfo.createAsymmetricChannelInfo()
        )
        // Two dummy-type infos of the same kind must be equal
        assertEquals(
            ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
            ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo()
        )
        assertEquals(
            ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyInfo(),
            ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyInfo()
        )
        assertEquals(
            ReceptionChannelInfo.createAnyObliviousChannelInfo(),
            ReceptionChannelInfo.createAnyObliviousChannelInfo()
        )
    }

    @Test
    fun testEqualsForObliviousChannel() {
        val a = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        val b = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        assertEquals(a, b)
    }

    @Test
    fun testEqualsForPreKeyChannel() {
        val a = ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)
        val b = ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)
        assertEquals(a, b)
    }

    @Test
    fun testNotEqualsForDifferentChannelTypes() {
        val local = ReceptionChannelInfo.createLocalChannelInfo()
        val asymmetric = ReceptionChannelInfo.createAsymmetricChannelInfo()
        val oblivious = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        val preKey = ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)

        assertFalse(local.equals(asymmetric))
        assertFalse(local.equals(oblivious))
        assertFalse(local.equals(preKey))
        assertFalse(asymmetric.equals(oblivious))
        assertFalse(oblivious.equals(preKey))
    }

    @Test
    fun testNotEqualsForObliviousDifferentUid() {
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32) { 7 }))
        val otherUid = UID(prng)

        val a = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        val b = ReceptionChannelInfo.createObliviousChannelInfo(otherUid, remoteIdentity)
        assertFalse(a.equals(b))
    }

    @Test
    fun testNotEqualsForObliviousDifferentIdentity() {
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32) { 9 }))
        val otherServerAuth = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val otherEncryption = EncryptionEciesCurve25519KeyPair.generate(prng)
        val otherIdentity = Identity(
            "other.olvid.com",
            otherServerAuth.publicKey as ServerAuthenticationPublicKey,
            otherEncryption.publicKey as EncryptionPublicKey
        )

        val a = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)
        val b = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, otherIdentity)
        assertFalse(a.equals(b))
    }

    @Test
    fun testNotEqualsForPreKeyDifferentUid() {
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32) { 7 }))
        val otherUid = UID(prng)

        val a = ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)
        val b = ReceptionChannelInfo.createPreKeyChannelInfo(otherUid, remoteIdentity)
        assertFalse(a.equals(b))
    }

    @Test
    fun testNotEqualsNonReceptionChannelInfoObject() {
        val local = ReceptionChannelInfo.createLocalChannelInfo()
        assertFalse(local.equals("not a ReceptionChannelInfo"))
        assertFalse(local.equals(null))
        assertFalse(local.equals(42))
    }

    // -----------------------------------------------------------------------
    // Oblivious legacy 4-element decode compatibility
    // -----------------------------------------------------------------------

    @Test
    fun testDecodeObliviousLegacyFourElementsSucceeds() {
        // The source code explicitly accepts length == 4 for legacy compatibility.
        // Build a 4-element encoded list: [type, uid, identity, <extra ignored>]
        val entries = arrayOf(
            io.olvid.engine.encoder.Encoded.of(ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE.toLong()),
            io.olvid.engine.encoder.Encoded.of(remoteDeviceUid),
            io.olvid.engine.encoder.Encoded.of(remoteIdentity),
            io.olvid.engine.encoder.Encoded.of(0L) // legacy extra element
        )
        val encoded = io.olvid.engine.encoder.Encoded.of(entries)
        val decoded = ReceptionChannelInfo.of(encoded)
        assertEquals(ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE, decoded.channelType)
        assertArrayEquals(remoteDeviceUid.bytes, decoded.remoteDeviceUid!!.bytes)
        assertEquals(remoteIdentity, decoded.remoteIdentity)
    }
}
