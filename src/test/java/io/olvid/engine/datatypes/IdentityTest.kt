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

import io.olvid.engine.crypto.MAC
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.metamanager.IdentityDelegate
import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.StandardCharsets

class IdentityTest {

    @Test
    fun testIdentityBasic() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        val serverName = "test.olvid.com"
        val serverPk = serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey
        val encryptionPk = encryptionKeyPair.publicKey as EncryptionPublicKey

        val identity = Identity(serverName, serverPk, encryptionPk)

        assertEquals(serverName, identity.server)
        assertEquals(serverPk, identity.serverAuthenticationPublicKey)
        assertEquals(encryptionPk, identity.encryptionPublicKey)

        // Verify getBytes caching (first call builds, second call returns cached)
        val bytes1 = identity.getBytes()
        val bytes2 = identity.getBytes()
        assertSame(bytes1, bytes2)

        // Verify UID generation
        val uid = identity.computeUniqueUid()
        assertNotNull(uid)

        // Verify toString
        val str = identity.toString()
        assertTrue(str.contains(serverName))
        assertTrue(str.contains("-"))
    }

    @Test
    fun testIdentityEqualsAndHashCode() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair1 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair1 = EncryptionEciesCurve25519KeyPair.generate(prng)

        val identity1 = Identity(
            "test.olvid.com",
            serverAuthKeyPair1.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair1.publicKey as EncryptionPublicKey
        )

        val identity1Copy = Identity(
            "test.olvid.com",
            serverAuthKeyPair1.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair1.publicKey as EncryptionPublicKey
        )

        val identity2 = Identity(
            "diff.olvid.com",
            serverAuthKeyPair1.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair1.publicKey as EncryptionPublicKey
        )

        // Same reference
        assertTrue(identity1.equals(identity1))

        // Identical contents
        assertTrue(identity1.equals(identity1Copy))
        assertEquals(identity1.hashCode(), identity1Copy.hashCode())

        // Non-identity object
        assertFalse(identity1.equals("Not an identity"))

        // Different contents
        assertFalse(identity1.equals(identity2))
    }

    @Test
    fun testIdentityCompareTo() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        val identity1 = Identity(
            "a.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val identity2 = Identity(
            "b.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val identity1Copy = Identity(
            "a.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        // Same
        assertEquals(0, identity1.compareTo(identity1Copy))

        // Different bytes, same length
        assertTrue(identity1.compareTo(identity2) < 0)
        assertTrue(identity2.compareTo(identity1) > 0)

        // Different length
        val identityLonger = Identity(
            "a.olvid.com-longer-server-name",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )
        assertTrue(identity1.compareTo(identityLonger) < 0)
        assertTrue(identityLonger.compareTo(identity1) > 0)
    }

    @Test
    fun testIdentityDecodingSuccess() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        val original = Identity(
            "decode.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val bytes = original.getBytes()
        val decoded = Identity.of(bytes)

        assertEquals(original, decoded)
        assertEquals(original.server, decoded.server)
        assertArrayEquals(original.serverAuthenticationPublicKey.compactKey, decoded.serverAuthenticationPublicKey.compactKey)
        assertArrayEquals(original.encryptionPublicKey.compactKey, decoded.encryptionPublicKey.compactKey)
    }

    @Test
    fun testIdentityDecodingFailures() {
        // 1. Missing zero byte separator
        try {
            Identity.of(byteArrayOf(1, 2, 3, 4))
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }

        // 2. Invalid server key algo implementation (e.g. 0x05)
        val bytesWithInvalidServerAlgo = "server".toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0, 5, 1, 2, 3)
        try {
            Identity.of(bytesWithInvalidServerAlgo)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }

        // 3. Short bytes for server key
        val bytesWithTruncatedServerKey = "server".toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0, 1, 2, 3) // Curve25519 algorithm implementation is 1
        try {
            Identity.of(bytesWithTruncatedServerKey)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }

        // 4. Invalid anon key algo implementation
        // Construct a partially valid byte array: server + 0 + serverKey (algorithm implementation 1, length 33 bytes) + invalid anon key impl (0x05)
        val serverKeyPart = byteArrayOf(1) + ByteArray(32) { 9 } // 33 bytes total
        val bytesWithInvalidAnonAlgo = "server".toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0) + serverKeyPart + byteArrayOf(5)
        try {
            Identity.of(bytesWithInvalidAnonAlgo)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }

        // 5. Truncated anon key
        val bytesWithTruncatedAnonKey = "server".toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0) + serverKeyPart + byteArrayOf(1, 2, 3)
        try {
            Identity.of(bytesWithTruncatedAnonKey)
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testPrivateIdentityBasic() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val mac = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = mac.generateKey(prng) as MACKey

        val publicIdentity = Identity(
            "private.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val privateIdentity = PrivateIdentity(
            publicIdentity,
            serverAuthKeyPair.getPrivateKey(),
            encryptionKeyPair.getPrivateKey(),
            macKey
        )

        assertEquals(publicIdentity, privateIdentity.publicIdentity)
        assertEquals(serverAuthKeyPair.getPrivateKey(), privateIdentity.serverAuthenticationPrivateKey)
        assertEquals(encryptionKeyPair.getPrivateKey(), privateIdentity.encryptionPrivateKey)
        assertEquals(macKey, privateIdentity.macKey)

        assertEquals(publicIdentity.computeUniqueUid(), privateIdentity.computeUniqueUid())
        assertEquals(publicIdentity.serverAuthenticationPublicKey, privateIdentity.getServerAuthenticationPublicKey())
        assertEquals(publicIdentity.encryptionPublicKey, privateIdentity.getEncryptionPublicKey())
    }

    @Test
    fun testPrivateIdentitySerializationAndDecoding() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val mac = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = mac.generateKey(prng) as MACKey

        val publicIdentity = Identity(
            "private.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val original = PrivateIdentity(
            publicIdentity,
            serverAuthKeyPair.getPrivateKey(),
            encryptionKeyPair.getPrivateKey(),
            macKey
        )

        val serialized = original.serialize()
        val decoded = PrivateIdentity.of(serialized)

        assertNotNull(decoded)
        assertEquals(original.publicIdentity, decoded!!.publicIdentity)
        assertArrayEquals(original.macKey.keyBytes, decoded.macKey.keyBytes)

        // Test decoding invalid bytes returns null
        val invalidDecoded = PrivateIdentity.of(byteArrayOf(1, 2, 3))
        assertNull(invalidDecoded)
    }

    @Test
    fun testDeterministicSeeds() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val mac = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = mac.generateKey(prng) as MACKey

        val publicIdentity = Identity(
            "private.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val privateIdentity = PrivateIdentity(
            publicIdentity,
            serverAuthKeyPair.getPrivateKey(),
            encryptionKeyPair.getPrivateKey(),
            macKey
        )

        val diversificationTag = byteArrayOf(1, 2, 3, 4)

        // 1. COMPUTE_SAS
        val seedSas = privateIdentity.getDeterministicSeedForOwnedIdentity(diversificationTag, IdentityDelegate.DeterministicSeedContext.COMPUTE_SAS)
        assertNotNull(seedSas)

        // 2. COMPUTE_TRANSFER_SAS
        val seedTransfer = privateIdentity.getDeterministicSeedForOwnedIdentity(diversificationTag, IdentityDelegate.DeterministicSeedContext.COMPUTE_TRANSFER_SAS)
        assertNotNull(seedTransfer)

        // 3. ENCRYPT_RETURN_RECEIPT
        val seedReceipt = privateIdentity.getDeterministicSeedForOwnedIdentity(diversificationTag, IdentityDelegate.DeterministicSeedContext.ENCRYPT_RETURN_RECEIPT)
        assertNotNull(seedReceipt)
    }

    @Test
    fun testDeterministicBackupSeedForLegacyIdentity() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val mac = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = mac.generateKey(prng) as MACKey

        val publicIdentity = Identity(
            "private.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val privateIdentity = PrivateIdentity(
            publicIdentity,
            serverAuthKeyPair.getPrivateKey(),
            encryptionKeyPair.getPrivateKey(),
            macKey
        )

        val backupSeed = privateIdentity.getDeterministicBackupSeedForLegacyIdentity()
        assertNotNull(backupSeed)
        assertEquals(BackupSeed.BACKUP_SEED_LENGTH, backupSeed.backupSeedBytes.size)
    }

    @Test
    fun testStaticDelegatorReflection() {
        // Test Identity.of(ByteArray) delegator
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        val identity = Identity(
            "reflection.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )
        val identityBytes = identity.getBytes()

        val identityMethod = Identity::class.java.getMethod("of", ByteArray::class.java)
        val invokedIdentity = identityMethod.invoke(null, identityBytes) as? Identity
        assertNotNull(invokedIdentity)
        assertEquals(identity, invokedIdentity)

        // Test PrivateIdentity.of(ByteArray) delegator
        val mac = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = mac.generateKey(prng) as MACKey
        val privateIdentity = PrivateIdentity(
            identity,
            serverAuthKeyPair.getPrivateKey(),
            encryptionKeyPair.getPrivateKey(),
            macKey
        )
        val privateIdentityBytes = privateIdentity.serialize()

        val privateIdentityMethod = PrivateIdentity::class.java.getMethod("of", ByteArray::class.java)
        val invokedPrivateIdentity = privateIdentityMethod.invoke(null, privateIdentityBytes) as? PrivateIdentity
        assertNotNull(invokedPrivateIdentity)
        assertEquals(privateIdentity.publicIdentity, invokedPrivateIdentity!!.publicIdentity)
    }
}
