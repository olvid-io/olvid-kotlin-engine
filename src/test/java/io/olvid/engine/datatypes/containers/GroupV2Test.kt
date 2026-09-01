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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncAES256ThenSHA256Key
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class GroupV2Test {

    private lateinit var prng: PRNGService

    @Before
    fun setup() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))
    }

    // ------------------------------------------------------------------
    // Helper to build a realistic Identity from the PRNG
    // ------------------------------------------------------------------
    private fun makeIdentity(): Identity {
        val serverAuthKP = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKP = EncryptionEciesCurve25519KeyPair.generate(prng)
        return Identity(
            "https://test.olvid.io",
            serverAuthKP.publicKey as ServerAuthenticationPublicKey,
            encKP.publicKey as EncryptionPublicKey
        )
    }

    // ------------------------------------------------------------------
    // Permission enum
    // ------------------------------------------------------------------

    @Test
    fun testPermissionStringRoundTrip() {
        for (permission in GroupV2.Permission.values()) {
            val s = permission.string
            assertNotNull("getString() must not return null for $permission", s)
            assertTrue("getString() must not be empty for $permission", s.isNotEmpty())
            assertEquals(
                "fromString(getString()) must round-trip for $permission",
                permission,
                GroupV2.Permission.fromString(s)
            )
        }
    }

    @Test
    fun testPermissionFromUnknownStringReturnsNull() {
        assertNull(GroupV2.Permission.fromString("unknown_perm"))
        assertNull(GroupV2.Permission.fromString(""))
    }

    @Test
    fun testPermissionSerializeDeserializeRoundTrip() {
        val permissions = mutableSetOf<GroupV2.Permission?>(
            GroupV2.Permission.GROUP_ADMIN,
            GroupV2.Permission.SEND_MESSAGE,
            GroupV2.Permission.CHANGE_SETTINGS
        )
        val serialized = GroupV2.Permission.serializePermissions(permissions)
        assertNotNull(serialized)
        val deserialized = GroupV2.Permission.deserializeKnownPermissions(serialized!!)
        assertEquals(permissions, deserialized)
    }

    @Test
    fun testPermissionSerializeDeserializeEmptySet() {
        val empty = mutableSetOf<GroupV2.Permission?>()
        val serialized = GroupV2.Permission.serializePermissions(empty)
        assertNotNull(serialized)
        assertEquals(0, serialized!!.size)
        val deserialized = GroupV2.Permission.deserializeKnownPermissions(serialized)
        assertTrue(deserialized.isEmpty())
    }

    @Test
    fun testPermissionSerializePermissionStringsRoundTrip() {
        val strings = mutableListOf("ga", "sm", "eo")
        val serialized = GroupV2.Permission.serializePermissionStrings(strings)
        assertNotNull(serialized)
        val deserialized = GroupV2.Permission.deserializePermissions(serialized!!)
        assertEquals(strings, deserialized)
    }

    @Test
    fun testDefaultPermissions() {
        val memberPerms = GroupV2.Permission.DEFAULT_MEMBER_PERMISSIONS.toSet()
        assertTrue(memberPerms.contains(GroupV2.Permission.SEND_MESSAGE))
        assertTrue(memberPerms.contains(GroupV2.Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES))
        assertFalse(memberPerms.contains(GroupV2.Permission.GROUP_ADMIN))

        val adminPerms = GroupV2.Permission.DEFAULT_ADMIN_PERMISSIONS.toSet()
        assertTrue(adminPerms.contains(GroupV2.Permission.GROUP_ADMIN))
        assertTrue(adminPerms.contains(GroupV2.Permission.SEND_MESSAGE))
        assertTrue(adminPerms.contains(GroupV2.Permission.CHANGE_SETTINGS))
    }

    // ------------------------------------------------------------------
    // Identifier round-trip
    // ------------------------------------------------------------------

    @Test
    fun testIdentifierEncodeDecodeServerCategory() {
        val uid = UID(prng)
        val original = GroupV2.Identifier(uid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val decoded = GroupV2.Identifier.of(original.encode())

        assertEquals(original.groupUid, decoded.groupUid)
        assertEquals(original.serverUrl, decoded.serverUrl)
        assertEquals(original.category, decoded.category)
        assertEquals(original, decoded)
    }

    @Test
    fun testIdentifierEncodeDecodeKeycloakCategory() {
        val uid = UID(prng)
        val original = GroupV2.Identifier(uid, "https://keycloak.example.com", GroupV2.Identifier.CATEGORY_KEYCLOAK)
        val decoded = GroupV2.Identifier.of(original.encode())

        assertEquals(original.groupUid, decoded.groupUid)
        assertEquals(original.serverUrl, decoded.serverUrl)
        assertEquals(original.category, decoded.category)
        assertEquals(original, decoded)
    }

    @Test
    fun testIdentifierBytesRoundTrip() {
        val uid = UID(prng)
        val original = GroupV2.Identifier(uid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val decoded = GroupV2.Identifier.of(original.bytes)

        assertEquals(original, decoded)
    }

    @Test
    fun testIdentifierEqualsAndHashCode() {
        val uid = UID(prng)
        val a = GroupV2.Identifier(uid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val b = GroupV2.Identifier(uid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())

        val differentUid = UID(prng)
        val c = GroupV2.Identifier(differentUid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        assertNotEquals(a, c)
    }

    @Test
    fun testIdentifierComputeProtocolInstanceUid() {
        val uid = UID(prng)
        val identifier = GroupV2.Identifier(uid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val protocolUid = identifier.computeProtocolInstanceUid()
        assertNotNull(protocolUid)
        // Deterministic: same identifier should produce same UID
        val protocolUid2 = identifier.computeProtocolInstanceUid()
        assertEquals(protocolUid, protocolUid2)
    }

    // ------------------------------------------------------------------
    // BlobKeys round-trip
    // ------------------------------------------------------------------

    @Test
    fun testBlobKeysEncodeDecodeWithAllFields() {
        val mainSeed = Seed(prng.bytes(32))
        val versionSeed = Seed(prng.bytes(32))
        val serverAuthKP = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val adminKey = serverAuthKP.privateKey as ServerAuthenticationPrivateKey

        val original = GroupV2.BlobKeys(mainSeed, versionSeed, adminKey)
        val decoded = GroupV2.BlobKeys.of(original.encode())

        assertArrayEquals(original.blobMainSeed!!.bytes, decoded.blobMainSeed!!.bytes)
        assertArrayEquals(original.blobVersionSeed!!.bytes, decoded.blobVersionSeed!!.bytes)
        assertNotNull(decoded.groupAdminServerAuthenticationPrivateKey)
    }

    @Test
    fun testBlobKeysEncodeDecodeNullOptionalFields() {
        val versionSeed = Seed(prng.bytes(32))

        val original = GroupV2.BlobKeys(null, versionSeed, null)
        val decoded = GroupV2.BlobKeys.of(original.encode())

        assertNull(decoded.blobMainSeed)
        assertArrayEquals(original.blobVersionSeed!!.bytes, decoded.blobVersionSeed!!.bytes)
        assertNull(decoded.groupAdminServerAuthenticationPrivateKey)
    }

    // ------------------------------------------------------------------
    // ServerPhotoInfo round-trip + equals
    // ------------------------------------------------------------------

    @Test
    fun testServerPhotoInfoEncodeDecodeWithIdentity() {
        val photoIdentity = makeIdentity()
        val photoLabel = UID(prng)
        val photoKey = AuthEncAES256ThenSHA256Key.generate(prng) as AuthEncKey

        val original = GroupV2.ServerPhotoInfo(photoIdentity, photoLabel, photoKey)
        val decoded = GroupV2.ServerPhotoInfo.of(original.encode())

        assertEquals(original, decoded)
        assertEquals(original.serverPhotoIdentity, decoded.serverPhotoIdentity)
        assertEquals(original.serverPhotoLabel, decoded.serverPhotoLabel)
    }

    @Test
    fun testServerPhotoInfoEncodeDecodeNullIdentity() {
        val photoLabel = UID(prng)
        val photoKey = AuthEncAES256ThenSHA256Key.generate(prng) as AuthEncKey

        val original = GroupV2.ServerPhotoInfo(null, photoLabel, photoKey)
        val decoded = GroupV2.ServerPhotoInfo.of(original.encode())

        assertEquals(original, decoded)
        assertNull(decoded.serverPhotoIdentity)
        assertEquals(original.serverPhotoLabel, decoded.serverPhotoLabel)
    }

    @Test
    fun testServerPhotoInfoEqualsDifferentLabel() {
        val photoLabel1 = UID(prng)
        val photoLabel2 = UID(prng)
        val photoKey = AuthEncAES256ThenSHA256Key.generate(prng) as AuthEncKey

        val a = GroupV2.ServerPhotoInfo(null, photoLabel1, photoKey)
        val b = GroupV2.ServerPhotoInfo(null, photoLabel2, photoKey)
        assertNotEquals(a, b)
    }

    // ------------------------------------------------------------------
    // IdentityAndPermissions round-trip + equals/isAdmin
    // ------------------------------------------------------------------

    @Test
    fun testIdentityAndPermissionsEncodeDecodeAdmin() {
        val identity = makeIdentity()
        val perms = hashSetOf(
            GroupV2.Permission.GROUP_ADMIN,
            GroupV2.Permission.SEND_MESSAGE,
            GroupV2.Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES,
            GroupV2.Permission.CHANGE_SETTINGS
        )
        val original = GroupV2.IdentityAndPermissions(identity, perms)
        val decoded = GroupV2.IdentityAndPermissions.of(original.encode())

        assertEquals(original.identity, decoded.identity)
        assertEquals(original.permissions, decoded.permissions)
        assertTrue(decoded.isAdmin)
    }

    @Test
    fun testIdentityAndPermissionsEncodeDecodeMember() {
        val identity = makeIdentity()
        val perms = hashSetOf(GroupV2.Permission.SEND_MESSAGE)
        val original = GroupV2.IdentityAndPermissions(identity, perms)
        val decoded = GroupV2.IdentityAndPermissions.of(original.encode())

        assertEquals(original.identity, decoded.identity)
        assertEquals(original.permissions, decoded.permissions)
        assertFalse(decoded.isAdmin)
    }

    @Test
    fun testIdentityAndPermissionsEqualsOnlyByIdentity() {
        val identity = makeIdentity()
        val perms1 = hashSetOf(GroupV2.Permission.SEND_MESSAGE)
        val perms2 = hashSetOf(GroupV2.Permission.GROUP_ADMIN, GroupV2.Permission.SEND_MESSAGE)

        val a = GroupV2.IdentityAndPermissions(identity, perms1)
        val b = GroupV2.IdentityAndPermissions(identity, perms2)
        // equals is identity-only
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())

        val otherIdentity = makeIdentity()
        val c = GroupV2.IdentityAndPermissions(otherIdentity, perms1)
        assertNotEquals(a, c)
    }

    // ------------------------------------------------------------------
    // IdentityAndPermissionsAndDetails round-trip + equals
    // ------------------------------------------------------------------

    @Test
    fun testIdentityAndPermissionsAndDetailsEncodeDecodeRoundTrip() {
        val identity = makeIdentity()
        val permStrings = mutableListOf("ga", "sm")
        val details = """{"firstName":"Alice","lastName":"Test"}"""
        val nonce = prng.bytes(32)

        val original = GroupV2.IdentityAndPermissionsAndDetails(identity, permStrings, details, nonce)
        val decoded = GroupV2.IdentityAndPermissionsAndDetails.of(original.encode())

        assertEquals(original.identity, decoded.identity)
        assertEquals(original.permissionStrings, decoded.permissionStrings)
        assertEquals(original.serializedIdentityDetails, decoded.serializedIdentityDetails)
        assertArrayEquals(original.groupInvitationNonce, decoded.groupInvitationNonce)
    }

    @Test
    fun testIdentityAndPermissionsAndDetailsEqualsOnlyByIdentity() {
        val identity = makeIdentity()
        val a = GroupV2.IdentityAndPermissionsAndDetails(identity, mutableListOf("sm"), "details1", ByteArray(32))
        val b = GroupV2.IdentityAndPermissionsAndDetails(identity, mutableListOf("ga"), "details2", ByteArray(32) { 1 })
        // equals is identity-only
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    // ------------------------------------------------------------------
    // IdentifierVersionAndKeys round-trip
    // ------------------------------------------------------------------

    @Test
    fun testIdentifierVersionAndKeysEncodeDecodeRoundTrip() {
        val uid = UID(prng)
        val identifier = GroupV2.Identifier(uid, "https://test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val versionSeed = Seed(prng.bytes(32))
        val blobKeys = GroupV2.BlobKeys(null, versionSeed, null)
        val version = 42

        val original = GroupV2.IdentifierVersionAndKeys(identifier, version, blobKeys)
        val decoded = GroupV2.IdentifierVersionAndKeys(original.encode())

        assertEquals(original.groupIdentifier, decoded.groupIdentifier)
        assertEquals(original.groupVersion, decoded.groupVersion)
        assertArrayEquals(original.blobKeys.blobVersionSeed!!.bytes, decoded.blobKeys.blobVersionSeed!!.bytes)
        assertNull(decoded.blobKeys.blobMainSeed)
    }

    // ------------------------------------------------------------------
    // InvitationCollectedData round-trip
    // ------------------------------------------------------------------

    @Test
    fun testInvitationCollectedDataEncodeDecodeRoundTrip() {
        val inviterIdentity = makeIdentity()
        val mainSeed = Seed(prng.bytes(32))
        val versionSeed = Seed(prng.bytes(32))
        val serverAuthKP = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val adminKey = serverAuthKP.privateKey as ServerAuthenticationPrivateKey

        val original = GroupV2.InvitationCollectedData(
            hashMapOf(inviterIdentity to mainSeed),
            hashSetOf(versionSeed),
            hashSetOf(adminKey)
        )
        val decoded = GroupV2.InvitationCollectedData.of(original.encode())

        assertEquals(1, decoded.inviterIdentityAndBlobMainSeedCandidates.size)
        assertEquals(1, decoded.blobVersionSeedCandidates.size)
        assertEquals(1, decoded.groupAdminServerAuthenticationPrivateKeyCandidates.size)

        val decodedMainSeed = decoded.inviterIdentityAndBlobMainSeedCandidates[inviterIdentity]
        assertNotNull(decodedMainSeed)
        assertArrayEquals(mainSeed.bytes, decodedMainSeed!!.bytes)

        val decodedVersionSeed = decoded.blobVersionSeedCandidates.first()
        assertArrayEquals(versionSeed.bytes, decodedVersionSeed.bytes)
    }

    @Test
    fun testInvitationCollectedDataEmptyRoundTrip() {
        val original = GroupV2.InvitationCollectedData()
        val decoded = GroupV2.InvitationCollectedData.of(original.encode())

        assertTrue(decoded.inviterIdentityAndBlobMainSeedCandidates.isEmpty())
        assertTrue(decoded.blobVersionSeedCandidates.isEmpty())
        assertTrue(decoded.groupAdminServerAuthenticationPrivateKeyCandidates.isEmpty())
    }

    @Test
    fun testInvitationCollectedDataAddBlobKeysCandidates() {
        val collected = GroupV2.InvitationCollectedData()
        val inviterIdentity = makeIdentity()
        val mainSeed = Seed(prng.bytes(32))
        val versionSeed = Seed(prng.bytes(32))
        val blobKeys = GroupV2.BlobKeys(mainSeed, versionSeed, null)

        collected.addBlobKeysCandidates(inviterIdentity, blobKeys)

        assertEquals(1, collected.inviterIdentityAndBlobMainSeedCandidates.size)
        assertEquals(1, collected.blobVersionSeedCandidates.size)
        assertEquals(0, collected.groupAdminServerAuthenticationPrivateKeyCandidates.size)
        assertArrayEquals(mainSeed.bytes, collected.inviterIdentityAndBlobMainSeedCandidates[inviterIdentity]!!.bytes)
    }

    // ------------------------------------------------------------------
    // getSharedBlobSecretKey
    // ------------------------------------------------------------------

    @Test
    fun testGetSharedBlobSecretKeyIsDeterministic() {
        val mainSeed = Seed(prng.bytes(32))
        val versionSeed = Seed(prng.bytes(32))

        val key1 = GroupV2.getSharedBlobSecretKey(mainSeed, versionSeed)
        val key2 = GroupV2.getSharedBlobSecretKey(mainSeed, versionSeed)

        assertNotNull(key1)
        assertNotNull(key2)
        // CryptographicKey.equals compares algorithmClass, algorithmImplementation, and the key map
        assertEquals(key1, key2)
    }

    @Test
    fun testGetSharedBlobSecretKeyDiffersOnDifferentSeeds() {
        val mainSeed1 = Seed(prng.bytes(32))
        val versionSeed = Seed(prng.bytes(32))
        val mainSeed2 = Seed(prng.bytes(32))

        val key1 = GroupV2.getSharedBlobSecretKey(mainSeed1, versionSeed)
        val key2 = GroupV2.getSharedBlobSecretKey(mainSeed2, versionSeed)

        assertNotEquals(key1, key2)
    }
}
