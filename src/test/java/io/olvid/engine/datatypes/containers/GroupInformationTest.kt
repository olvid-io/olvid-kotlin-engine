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
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class GroupInformationTest {

    private lateinit var ownerIdentity: Identity
    private lateinit var groupUid: UID
    private val serializedDetails = """{"name":"Test Group","description":"A test group"}"""

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

        val seed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(seed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        ownerIdentity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        groupUid = UID(prng)
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    @Test
    fun testConstructorStoresFields() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)

        assertEquals(ownerIdentity, info.groupOwnerIdentity)
        assertEquals(groupUid, info.groupUid)
        assertEquals(serializedDetails, info.serializedGroupDetailsWithVersionAndPhoto)
    }

    // -------------------------------------------------------------------------
    // encode / of round-trip
    // -------------------------------------------------------------------------

    @Test
    fun testEncodeDecodeRoundTrip() {
        val original = GroupInformation(ownerIdentity, groupUid, serializedDetails)
        val encoded: Encoded = original.encode()
        val decoded: GroupInformation = GroupInformation.of(encoded)

        assertEquals(original.groupOwnerIdentity, decoded.groupOwnerIdentity)
        assertEquals(original.groupUid, decoded.groupUid)
        assertEquals(original.serializedGroupDetailsWithVersionAndPhoto, decoded.serializedGroupDetailsWithVersionAndPhoto)
    }

    @Test
    fun testEncodeDecodePreservesUidBytes() {
        val original = GroupInformation(ownerIdentity, groupUid, serializedDetails)
        val decoded = GroupInformation.of(original.encode())

        assertArrayEquals(original.groupUid.bytes, decoded.groupUid.bytes)
    }

    @Test
    fun testEncodeDecodeWithEmptyDetails() {
        val original = GroupInformation(ownerIdentity, groupUid, "")
        val decoded = GroupInformation.of(original.encode())

        assertEquals("", decoded.serializedGroupDetailsWithVersionAndPhoto)
    }

    @Test
    fun testEncodeDecodeWithUnicodeDetails() {
        val unicodeDetails = "日本語テスト😀"
        val original = GroupInformation(ownerIdentity, groupUid, unicodeDetails)
        val decoded = GroupInformation.of(original.encode())

        assertEquals(unicodeDetails, decoded.serializedGroupDetailsWithVersionAndPhoto)
    }

    @Test
    fun testDecodeWrongListLengthThrows() {
        // Encode a list with only 2 elements instead of 3
        val badEncoded = Encoded.of(arrayOf(
            Encoded.of(ownerIdentity),
            Encoded.of(groupUid)
        ))
        try {
            GroupInformation.of(badEncoded)
            fail("Expected DecodingException for list length != 3")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testDecodeWrongListLengthFourElementsThrows() {
        val seed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(seed)
        val extraUid = UID(prng)
        val badEncoded = Encoded.of(arrayOf(
            Encoded.of(ownerIdentity),
            Encoded.of(groupUid),
            Encoded.of(serializedDetails),
            Encoded.of(extraUid)
        ))
        try {
            GroupInformation.of(badEncoded)
            fail("Expected DecodingException for list length != 3")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // -------------------------------------------------------------------------
    // generate
    // -------------------------------------------------------------------------

    @Test
    fun testGenerateProducesValidObject() {
        val seed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(seed)

        val info = GroupInformation.generate(ownerIdentity, serializedDetails, prng)

        assertNotNull(info)
        assertEquals(ownerIdentity, info.groupOwnerIdentity)
        assertEquals(serializedDetails, info.serializedGroupDetailsWithVersionAndPhoto)
        assertNotNull(info.groupUid)
        assertEquals(UID.UID_LENGTH, info.groupUid.bytes.size)
    }

    @Test
    fun testGenerateProducesDifferentUidsEachCall() {
        val seed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(seed)

        val info1 = GroupInformation.generate(ownerIdentity, serializedDetails, prng)
        val info2 = GroupInformation.generate(ownerIdentity, serializedDetails, prng)

        // UIDs drawn from a PRNG should differ
        assertNotSame(info1.groupUid, info2.groupUid)
        // Extremely unlikely to collide with a properly seeded PRNG
        assertNotEquals(
            "Two successive generate() calls must yield distinct UIDs",
            info1.groupUid, info2.groupUid
        )
    }

    // -------------------------------------------------------------------------
    // computeProtocolUid (instance and static)
    // -------------------------------------------------------------------------

    @Test
    fun testComputeProtocolUidIsDeterministic() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)

        val uid1 = info.computeProtocolUid()
        val uid2 = info.computeProtocolUid()

        assertArrayEquals(uid1.bytes, uid2.bytes)
    }

    @Test
    fun testComputeProtocolUidInstanceMatchesStatic() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)

        val instanceUid = info.computeProtocolUid()
        val staticUid = GroupInformation.computeProtocolUid(
            ownerIdentity.getBytes(),
            groupUid.bytes
        )

        assertArrayEquals(instanceUid.bytes, staticUid.bytes)
    }

    @Test
    fun testComputeProtocolUidHasCorrectLength() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)
        val uid = info.computeProtocolUid()

        assertEquals(UID.UID_LENGTH, uid.bytes.size)
    }

    @Test
    fun testComputeProtocolUidDiffersForDifferentUids() {
        val seed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(seed)
        val otherUid = UID(prng)

        val uid1 = GroupInformation.computeProtocolUid(ownerIdentity.getBytes(), groupUid.bytes)
        val uid2 = GroupInformation.computeProtocolUid(ownerIdentity.getBytes(), otherUid.bytes)

        assertNotEquals(
            "computeProtocolUid must differ when groupUid differs",
            uid1, uid2
        )
    }

    @Test
    fun testComputeProtocolUidDiffersForDifferentOwners() {
        val seed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(seed)

        val serverAuthKeyPair2 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair2 = EncryptionEciesCurve25519KeyPair.generate(prng)
        val otherOwner = Identity(
            "other.olvid.io",
            serverAuthKeyPair2.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair2.publicKey as EncryptionPublicKey
        )

        val uid1 = GroupInformation.computeProtocolUid(ownerIdentity.getBytes(), groupUid.bytes)
        val uid2 = GroupInformation.computeProtocolUid(otherOwner.getBytes(), groupUid.bytes)

        assertNotEquals(
            "computeProtocolUid must differ when owner identity differs",
            uid1, uid2
        )
    }

    // -------------------------------------------------------------------------
    // getGroupOwnerAndUid
    // -------------------------------------------------------------------------

    @Test
    fun testGetGroupOwnerAndUidLength() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)
        val ownerAndUid = info.getGroupOwnerAndUid()

        val expectedLength = ownerIdentity.getBytes().size + UID.UID_LENGTH
        assertEquals(expectedLength, ownerAndUid.size)
    }

    @Test
    fun testGetGroupOwnerAndUidContents() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)
        val ownerAndUid = info.getGroupOwnerAndUid()

        val ownerBytes = ownerIdentity.getBytes()
        val uidBytes = groupUid.bytes

        // First part must match the owner identity bytes
        assertArrayEquals(ownerBytes, ownerAndUid.copyOfRange(0, ownerBytes.size))
        // Trailing part must match the group UID bytes
        assertArrayEquals(uidBytes, ownerAndUid.copyOfRange(ownerBytes.size, ownerAndUid.size))
    }

    @Test
    fun testGetGroupOwnerAndUidIsDeterministic() {
        val info = GroupInformation(ownerIdentity, groupUid, serializedDetails)

        assertArrayEquals(info.getGroupOwnerAndUid(), info.getGroupOwnerAndUid())
    }
}
