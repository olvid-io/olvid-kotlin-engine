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
import io.olvid.engine.crypto.AuthEnc
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ServerQueryTest {

    private lateinit var prng: PRNGService
    private lateinit var ownedIdentity: Identity
    private lateinit var deviceUid: UID
    private lateinit var authEncKey: AuthEncKey

    @Before
    fun setup() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        ownedIdentity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )
        deviceUid = UID(prng)
        authEncKey = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!.generateKey(prng) as AuthEncKey
    }

    // -------------------------------------------------------------------------
    // 1. TypeId enum — name + ordinal stability
    // -------------------------------------------------------------------------

    @Test
    fun testTypeIdNamesAreStable() {
        assertEquals("DEVICE_DISCOVERY_QUERY_ID", ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID.name)
        assertEquals("PUT_USER_DATA_QUERY_ID", ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID.name)
        assertEquals("GET_USER_DATA_QUERY_ID", ServerQuery.TypeId.GET_USER_DATA_QUERY_ID.name)
        assertEquals("CHECK_KEYCLOAK_REVOCATION_QUERY_ID", ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID.name)
        assertEquals("CREATE_GROUP_BLOB_QUERY_ID", ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID.name)
        assertEquals("GET_GROUP_BLOB_QUERY_ID", ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID.name)
        assertEquals("LOCK_GROUP_BLOB_QUERY_ID", ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID.name)
        assertEquals("UPDATE_GROUP_BLOB_QUERY_ID", ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID.name)
        assertEquals("PUT_GROUP_LOG_QUERY_ID", ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID.name)
        assertEquals("DELETE_GROUP_BLOB_QUERY_ID", ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID.name)
        assertEquals("GET_KEYCLOAK_DATA_QUERY_ID", ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID.name)
        assertEquals("OWNED_DEVICE_DISCOVERY_QUERY_ID", ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID.name)
        assertEquals("DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID", ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID.name)
        assertEquals("DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID", ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID.name)
        assertEquals("DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID", ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID.name)
        assertEquals("REGISTER_API_KEY_QUERY_ID", ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID.name)
        assertEquals("UPLOAD_PRE_KEY_QUERY_ID", ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID.name)
        assertEquals("TRANSFER_SOURCE_QUERY_ID", ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID.name)
        assertEquals("TRANSFER_TARGET_QUERY_ID", ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID.name)
        assertEquals("TRANSFER_RELAY_QUERY_ID", ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID.name)
        assertEquals("TRANSFER_WAIT_QUERY_ID", ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID.name)
        assertEquals("TRANSFER_CLOSE_QUERY_ID", ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID.name)
        assertEquals("BACKUPS_V2_CREATE_BACKUP_QUERY_ID", ServerQuery.TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID.name)
        assertEquals("BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID", ServerQuery.TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID.name)
        assertEquals("BACKUPS_V2_DELETE_BACKUP_QUERY_ID", ServerQuery.TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID.name)
        assertEquals("BACKUPS_V2_LIST_BACKUPS_QUERY_ID", ServerQuery.TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID.name)
        assertEquals("BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID", ServerQuery.TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID.name)
        assertEquals("KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE", ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE.name)
        assertEquals("KEYCLOAK_ID_BASED_AUTH_GET_SESSION", ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION.name)
    }

    @Test
    fun testTypeIdIntValuesAreStable() {
        assertEquals(0, ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID.value)
        assertEquals(1, ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID.value)
        assertEquals(2, ServerQuery.TypeId.GET_USER_DATA_QUERY_ID.value)
        assertEquals(3, ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID.value)
        assertEquals(4, ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID.value)
        assertEquals(5, ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID.value)
        assertEquals(6, ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID.value)
        assertEquals(7, ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID.value)
        assertEquals(8, ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID.value)
        assertEquals(9, ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID.value)
        assertEquals(10, ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID.value)
        assertEquals(11, ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID.value)
        assertEquals(12, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID.value)
        assertEquals(13, ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID.value)
        assertEquals(14, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID.value)
        assertEquals(15, ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID.value)
        assertEquals(16, ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID.value)
        assertEquals(1000, ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID.value)
        assertEquals(1001, ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID.value)
        assertEquals(1002, ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID.value)
        assertEquals(1003, ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID.value)
        assertEquals(1004, ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID.value)
        assertEquals(2000, ServerQuery.TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID.value)
        assertEquals(2001, ServerQuery.TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID.value)
        assertEquals(2002, ServerQuery.TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID.value)
        assertEquals(2003, ServerQuery.TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID.value)
        assertEquals(2004, ServerQuery.TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID.value)
        assertEquals(3000, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE.value)
        assertEquals(3001, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION.value)
    }

    // -------------------------------------------------------------------------
    // Helper: encode a Type, decode it via Type.of, assert the right class comes back.
    // -------------------------------------------------------------------------
    private fun roundTripType(type: ServerQuery.Type): ServerQuery.Type {
        val encoded = type.encode()
        return ServerQuery.Type.of(encoded)
    }

    // -------------------------------------------------------------------------
    // 2. Device category
    // -------------------------------------------------------------------------

    @Test
    fun testDeviceDiscoveryQueryRoundTrip() {
        val contactServerAuthKP = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val contactEncKP = EncryptionEciesCurve25519KeyPair.generate(prng)
        val contactIdentity = Identity(
            "contact.olvid.io",
            contactServerAuthKP.publicKey as ServerAuthenticationPublicKey,
            contactEncKP.publicKey as EncryptionPublicKey
        )

        val original = ServerQuery.DeviceDiscoveryQuery(contactIdentity)
        assertEquals(ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID, original.id)
        assertEquals("contact.olvid.io", original.server)

        val decoded = roundTripType(original) as ServerQuery.DeviceDiscoveryQuery
        assertEquals(ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID, decoded.id)
        assertEquals(contactIdentity, decoded.identity)
        assertEquals("contact.olvid.io", decoded.server)
    }

    @Test
    fun testOwnedDeviceDiscoveryQueryRoundTrip() {
        val original = ServerQuery.OwnedDeviceDiscoveryQuery(ownedIdentity)
        assertEquals(ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.OwnedDeviceDiscoveryQuery
        assertEquals(ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID, decoded.id)
        assertEquals(ownedIdentity.server, decoded.server)
    }

    // -------------------------------------------------------------------------
    // 3. User data category
    // -------------------------------------------------------------------------

    @Test
    fun testPutUserDataQueryRoundTrip() {
        val serverLabel = UID(prng)
        val dataUrl = "relative/path/to/data"

        val original = ServerQuery.PutUserDataQuery(ownedIdentity, serverLabel, dataUrl, authEncKey)
        assertEquals(ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.PutUserDataQuery
        assertEquals(ownedIdentity, decoded.ownedIdentity)
        assertEquals(serverLabel, decoded.serverLabel)
        assertEquals(dataUrl, decoded.dataUrl)
        assertEquals(authEncKey, decoded.dataKey)
    }

    @Test
    fun testGetUserDataQueryRoundTrip() {
        val serverLabel = UID(prng)

        val original = ServerQuery.GetUserDataQuery(ownedIdentity, serverLabel, true)
        assertEquals(ServerQuery.TypeId.GET_USER_DATA_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.GetUserDataQuery
        assertEquals(ownedIdentity, decoded.identity)
        assertEquals(serverLabel, decoded.serverLabel)
        assertEquals(true, decoded.retryIfNotFound)
    }

    @Test
    fun testGetUserDataQueryLegacyTwoElementEncodingDecodesWithRetryFalse() {
        // Legacy GetUserDataQuery instances persisted before MR 290 only have 2 encoded parts
        // (identity, serverLabel); they must still decode with retryIfNotFound defaulting to false.
        val serverLabel = UID(prng)
        val legacyParts = arrayOf(Encoded.of(ownedIdentity), Encoded.of(serverLabel))

        val decoded = ServerQuery.GetUserDataQuery(ownedIdentity.server, legacyParts)
        assertEquals(ownedIdentity, decoded.identity)
        assertEquals(serverLabel, decoded.serverLabel)
        assertEquals(false, decoded.retryIfNotFound)
    }

    // -------------------------------------------------------------------------
    // 4. Keycloak category
    // -------------------------------------------------------------------------

    @Test
    fun testCheckKeycloakRevocationQueryRoundTrip() {
        val keycloakUrl = "https://keycloak.example.com/auth"
        val signedContactDetails = "eyJhbGciOiJSUzI1NiJ9.payload.signature"

        val original = ServerQuery.CheckKeycloakRevocationQuery(keycloakUrl, signedContactDetails)
        assertEquals(ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.CheckKeycloakRevocationQuery
        assertEquals(keycloakUrl, decoded.server)
        assertEquals(signedContactDetails, decoded.signedContactDetails)
    }

    @Test
    fun testGetKeycloakDataQueryRoundTrip() {
        val serverLabel = UID(prng)
        val serverUrl = "https://keycloak.example.com/auth"

        val original = ServerQuery.GetKeycloakDataQuery(serverUrl, serverLabel)
        assertEquals(ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.GetKeycloakDataQuery
        assertEquals(serverUrl, decoded.server)
        assertEquals(serverLabel, decoded.serverLabel)
    }

    // -------------------------------------------------------------------------
    // 5. Group blob category
    // -------------------------------------------------------------------------

    @Test
    fun testCreateGroupBlobQueryRoundTrip() {
        val groupUid = UID(prng)
        val groupIdentifier = GroupV2.Identifier(groupUid, "group.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val encryptedBlob = EncryptedBytes(ByteArray(64) { it.toByte() })
        val encodedAdminPublicKey = Encoded.of(ByteArray(32) { 0x42 })

        val original = ServerQuery.CreateGroupBlobQuery(groupIdentifier, encodedAdminPublicKey, encryptedBlob)
        assertEquals(ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.CreateGroupBlobQuery
        assertEquals(groupUid, decoded.groupUid)
        assertArrayEquals(encryptedBlob.bytes, decoded.encryptedBlob.bytes)
        assertArrayEquals(encodedAdminPublicKey.bytes, decoded.encodedGroupAdminPublicKey!!.bytes)
    }

    @Test
    fun testGetGroupBlobQueryRoundTrip() {
        val groupUid = UID(prng)
        val groupIdentifier = GroupV2.Identifier(groupUid, "group.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val nonce = ByteArray(16) { it.toByte() }

        val original = ServerQuery.GetGroupBlobQuery(groupIdentifier, nonce)
        assertEquals(ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.GetGroupBlobQuery
        assertEquals(groupUid, decoded.groupUid)
        assertArrayEquals(nonce, decoded.serverQueryNonce)
    }

    @Test
    fun testLockGroupBlobQueryRoundTrip() {
        val groupUid = UID(prng)
        val groupIdentifier = GroupV2.Identifier(groupUid, "group.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val lockNonce = ByteArray(16) { (it + 1).toByte() }
        val signature = ByteArray(64) { (it * 2).toByte() }

        val original = ServerQuery.LockGroupBlobQuery(groupIdentifier, lockNonce, signature)
        assertEquals(ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.LockGroupBlobQuery
        assertEquals(groupUid, decoded.groupUid)
        assertArrayEquals(lockNonce, decoded.lockNonce)
        assertArrayEquals(signature, decoded.signature)
    }

    @Test
    fun testUpdateGroupBlobQueryRoundTrip() {
        val groupUid = UID(prng)
        val groupIdentifier = GroupV2.Identifier(groupUid, "group.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val lockNonce = ByteArray(16) { (it + 5).toByte() }
        val encryptedBlob = EncryptedBytes(ByteArray(128) { it.toByte() })
        val encodedAdminPublicKey = Encoded.of(ByteArray(32) { 0x11 })
        val signature = ByteArray(64) { (it + 3).toByte() }

        val original = ServerQuery.UpdateGroupBlobQuery(groupIdentifier, lockNonce, encryptedBlob, encodedAdminPublicKey, signature)
        assertEquals(ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.UpdateGroupBlobQuery
        assertEquals(groupUid, decoded.groupUid)
        assertArrayEquals(lockNonce, decoded.lockNonce)
        assertArrayEquals(encryptedBlob.bytes, decoded.encryptedBlob.bytes)
        assertArrayEquals(encodedAdminPublicKey.bytes, decoded.encodedGroupAdminPublicKey!!.bytes)
        assertArrayEquals(signature, decoded.signature)
    }

    @Test
    fun testDeleteGroupBlobQueryRoundTrip() {
        val groupUid = UID(prng)
        val groupIdentifier = GroupV2.Identifier(groupUid, "group.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val signature = ByteArray(64) { it.toByte() }

        val original = ServerQuery.DeleteGroupBlobQuery(groupIdentifier, signature)
        assertEquals(ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.DeleteGroupBlobQuery
        assertEquals(groupUid, decoded.groupUid)
        assertArrayEquals(signature, decoded.signature)
    }

    // -------------------------------------------------------------------------
    // 6. Device management category
    // -------------------------------------------------------------------------

    @Test
    fun testDeviceManagementSetNicknameQueryRoundTrip() {
        val encryptedDeviceName = EncryptedBytes(ByteArray(48) { it.toByte() })

        val original = ServerQuery.DeviceManagementSetNicknameQuery(ownedIdentity, deviceUid, encryptedDeviceName, true)
        assertEquals(ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.DeviceManagementSetNicknameQuery
        assertEquals(deviceUid, decoded.deviceUid)
        assertArrayEquals(encryptedDeviceName.bytes, decoded.encryptedDeviceName.bytes)
        assertEquals(true, decoded.isCurrentDevice)

        // Also verify isCurrentDevice=false is preserved
        val original2 = ServerQuery.DeviceManagementSetNicknameQuery(ownedIdentity, deviceUid, encryptedDeviceName, false)
        val decoded2 = roundTripType(original2) as ServerQuery.DeviceManagementSetNicknameQuery
        assertEquals(false, decoded2.isCurrentDevice)
    }

    @Test
    fun testDeviceManagementDeactivateDeviceQueryRoundTrip() {
        val original = ServerQuery.DeviceManagementDeactivateDeviceQuery(ownedIdentity, deviceUid)
        assertEquals(ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.DeviceManagementDeactivateDeviceQuery
        assertEquals(deviceUid, decoded.deviceUid)
    }

    @Test
    fun testDeviceManagementSetUnexpiringDeviceQueryRoundTrip() {
        val original = ServerQuery.DeviceManagementSetUnexpiringDeviceQuery(ownedIdentity, deviceUid)
        assertEquals(ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.DeviceManagementSetUnexpiringDeviceQuery
        assertEquals(deviceUid, decoded.deviceUid)
    }

    // -------------------------------------------------------------------------
    // 7. API key / pre-key
    // -------------------------------------------------------------------------

    @Test
    fun testRegisterApiKeyQueryRoundTrip() {
        val token = ByteArray(32) { it.toByte() }
        val apiKey = "550e8400-e29b-41d4-a716-446655440000"

        val original = ServerQuery.RegisterApiKeyQuery(ownedIdentity, token, apiKey)
        assertEquals(ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.RegisterApiKeyQuery
        assertEquals(apiKey, decoded.apiKeyString)
        assertArrayEquals(token, decoded.serverSessionToken)
    }

    @Test
    fun testUploadPreKeyQueryRoundTrip() {
        val preKeyBytes = ByteArray(80) { it.toByte() }

        val original = ServerQuery.UploadPreKeyQuery(ownedIdentity, deviceUid, preKeyBytes)
        assertEquals(ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.UploadPreKeyQuery
        assertEquals(deviceUid, decoded.deviceUid)
        assertArrayEquals(preKeyBytes, decoded.preKeyBytes)
    }

    // -------------------------------------------------------------------------
    // 8. Transfer category (all are WebSocket)
    // -------------------------------------------------------------------------

    @Test
    fun testTransferSourceQueryRoundTrip() {
        val original = ServerQuery.TransferSourceQuery()
        assertEquals(ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID, original.id)
        assertTrue(original.isWebSocket)

        val decoded = roundTripType(original) as ServerQuery.TransferSourceQuery
        assertEquals(ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID, decoded.id)
    }

    @Test
    fun testTransferTargetQueryRoundTrip() {
        val sessionNumber = 987654321L
        val payload = ByteArray(40) { it.toByte() }

        val original = ServerQuery.TransferTargetQuery(sessionNumber, payload)
        assertEquals(ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID, original.id)
        assertTrue(original.isWebSocket)

        val decoded = roundTripType(original) as ServerQuery.TransferTargetQuery
        assertEquals(sessionNumber, decoded.sessionNumber)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun testTransferRelayQueryRoundTrip() {
        val connectionId = "conn-abc-123"
        val payload = ByteArray(32) { (it + 10).toByte() }

        val original = ServerQuery.TransferRelayQuery(connectionId, payload, true)
        assertEquals(ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID, original.id)
        assertTrue(original.isWebSocket)

        val decoded = roundTripType(original) as ServerQuery.TransferRelayQuery
        assertEquals(connectionId, decoded.connectionIdentifier)
        assertArrayEquals(payload, decoded.payload)
        assertEquals(true, decoded.noResponseExpected)

        val original2 = ServerQuery.TransferRelayQuery(connectionId, payload, false)
        val decoded2 = roundTripType(original2) as ServerQuery.TransferRelayQuery
        assertEquals(false, decoded2.noResponseExpected)
    }

    @Test
    fun testTransferWaitQueryRoundTrip() {
        val original = ServerQuery.TransferWaitQuery()
        assertEquals(ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID, original.id)
        assertTrue(original.isWebSocket)

        val decoded = roundTripType(original) as ServerQuery.TransferWaitQuery
        assertEquals(ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID, decoded.id)
    }

    @Test
    fun testTransferCloseQueryRoundTrip() {
        val original = ServerQuery.TransferCloseQuery(true)
        assertEquals(ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID, original.id)
        assertTrue(original.isWebSocket)

        val decoded = roundTripType(original) as ServerQuery.TransferCloseQuery
        assertEquals(true, decoded.abort)

        val decoded2 = roundTripType(ServerQuery.TransferCloseQuery(false)) as ServerQuery.TransferCloseQuery
        assertEquals(false, decoded2.abort)
    }

    // -------------------------------------------------------------------------
    // 9. PutGroupLogQuery — group log with signature
    // -------------------------------------------------------------------------

    @Test
    fun testPutGroupLogQueryRoundTrip() {
        val groupUid = UID(prng)
        val groupIdentifier = GroupV2.Identifier(groupUid, "group.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        val signature = ByteArray(64) { (it * 3).toByte() }

        val original = ServerQuery.PutGroupLogQuery(groupIdentifier, signature)
        assertEquals(ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID, original.id)

        val decoded = roundTripType(original) as ServerQuery.PutGroupLogQuery
        assertEquals(groupUid, decoded.groupUid)
        assertArrayEquals(signature, decoded.signature)
    }

    // -------------------------------------------------------------------------
    // 10. ServerQuery wrapper round-trip (encode + ServerQuery.of)
    // -------------------------------------------------------------------------

    @Test
    fun testServerQueryWrapperRoundTripDeviceDiscovery() {
        val contactServerAuthKP = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val contactEncKP = EncryptionEciesCurve25519KeyPair.generate(prng)
        val contactIdentity = Identity(
            "contact.olvid.io",
            contactServerAuthKP.publicKey as ServerAuthenticationPublicKey,
            contactEncKP.publicKey as EncryptionPublicKey
        )

        val type = ServerQuery.DeviceDiscoveryQuery(contactIdentity)
        val dummyElements = Encoded.of(ByteArray(0))
        val query = ServerQuery(dummyElements, ownedIdentity, type)

        val encoded = query.encode()
        val decoded = ServerQuery.of(encoded)

        assertNotNull(decoded)
        assertEquals(ownedIdentity, decoded.ownedIdentity)
        assertTrue(decoded.type is ServerQuery.DeviceDiscoveryQuery)
        val decodedType = decoded.type as ServerQuery.DeviceDiscoveryQuery
        assertEquals(contactIdentity, decodedType.identity)
    }

    @Test
    fun testServerQueryWrapperRoundTripTransferRelay() {
        val connectionId = "relay-conn-456"
        val payload = ByteArray(20) { it.toByte() }
        val type = ServerQuery.TransferRelayQuery(connectionId, payload, false)

        val dummyElements = Encoded.of(ByteArray(0))
        // Transfer queries use an empty ownedIdentity-equivalent — the identity field is still stored
        val query = ServerQuery(dummyElements, ownedIdentity, type)

        val encoded = query.encode()
        val decoded = ServerQuery.of(encoded)

        assertNotNull(decoded)
        assertTrue(decoded.type is ServerQuery.TransferRelayQuery)
        val decodedType = decoded.type as ServerQuery.TransferRelayQuery
        assertEquals(connectionId, decodedType.connectionIdentifier)
        assertArrayEquals(payload, decodedType.payload)
        assertEquals(false, decodedType.noResponseExpected)
        assertTrue(decoded.isWebSocket)
    }

    // -------------------------------------------------------------------------
    // 11. isWebSocket dispatch
    // -------------------------------------------------------------------------

    @Test
    fun testIsWebSocketClassification() {
        // HTTP queries
        assertEquals(false, ServerQuery.DeviceDiscoveryQuery(ownedIdentity).isWebSocket)
        assertEquals(false, ServerQuery.OwnedDeviceDiscoveryQuery(ownedIdentity).isWebSocket)
        assertEquals(false, ServerQuery.GetUserDataQuery(ownedIdentity, UID(prng), false).isWebSocket)
        assertEquals(false, ServerQuery.DeviceManagementDeactivateDeviceQuery(ownedIdentity, deviceUid).isWebSocket)
        assertEquals(false, ServerQuery.UploadPreKeyQuery(ownedIdentity, deviceUid, ByteArray(8)).isWebSocket)

        // WebSocket queries
        assertEquals(true, ServerQuery.TransferSourceQuery().isWebSocket)
        assertEquals(true, ServerQuery.TransferTargetQuery(42L, ByteArray(4)).isWebSocket)
        assertEquals(true, ServerQuery.TransferRelayQuery("id", ByteArray(4), false).isWebSocket)
        assertEquals(true, ServerQuery.TransferWaitQuery().isWebSocket)
        assertEquals(true, ServerQuery.TransferCloseQuery(false).isWebSocket)
    }

    // -------------------------------------------------------------------------
    // 12. Negative paths
    // -------------------------------------------------------------------------

    @Test(expected = DecodingException::class)
    fun testTypeOfThrowsDecodingExceptionOnUnknownTypeId() {
        // Encode a list with an unknown int TypeId value (e.g. 9999)
        val encoded = Encoded.of(arrayOf(
            Encoded.of(9999L),
            Encoded.of("some.server.io"),
            Encoded.of(emptyArray<Encoded>())
        ))
        ServerQuery.Type.of(encoded)
    }

    @Test(expected = DecodingException::class)
    fun testTypeOfThrowsDecodingExceptionOnWrongListLength() {
        // Encode a list with only 2 elements instead of 3
        val encoded = Encoded.of(arrayOf(
            Encoded.of(0L),
            Encoded.of("some.server.io")
        ))
        ServerQuery.Type.of(encoded)
    }

    @Test(expected = DecodingException::class)
    fun testServerQueryOfThrowsDecodingExceptionOnWrongListLength() {
        // Encode a list with only 2 elements instead of 3
        val encoded = Encoded.of(arrayOf(
            Encoded.of(ByteArray(0)),
            Encoded.of(ownedIdentity)
        ))
        ServerQuery.of(encoded)
    }

    @Test(expected = DecodingException::class)
    fun testTypeOfThrowsOnBackupV2TypeId() {
        // BackupsV2 TypeIds are explicitly excluded from decoding (they throw DecodingException)
        val encoded = Encoded.of(arrayOf(
            Encoded.of(2000L), // BACKUPS_V2_CREATE_BACKUP_QUERY_ID
            Encoded.of("backup.server.io"),
            Encoded.of(emptyArray<Encoded>())
        ))
        ServerQuery.Type.of(encoded)
    }

    @Test(expected = DecodingException::class)
    fun testDeviceDiscoveryQueryDecodingThrowsOnWrongPartCount() {
        ServerQuery.DeviceDiscoveryQuery("server.io", emptyArray())
    }

    @Test(expected = DecodingException::class)
    fun testPutUserDataQueryDecodingThrowsOnWrongPartCount() {
        ServerQuery.PutUserDataQuery("server.io", emptyArray())
    }

    @Test(expected = DecodingException::class)
    fun testTransferTargetQueryDecodingThrowsOnWrongPartCount() {
        ServerQuery.TransferTargetQuery(emptyArray())
    }

    @Test(expected = DecodingException::class)
    fun testTransferCloseQueryDecodingThrowsOnWrongPartCount() {
        ServerQuery.TransferCloseQuery(emptyArray())
    }
}
