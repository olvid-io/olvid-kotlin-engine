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

import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.containers.PreKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.*
import org.junit.Test
import java.util.HashMap

class PreKeyBlobOnServerTest {

    @Test
    fun testConstructorAndFields() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyId = KeyId(ByteArray(32) { 1 })
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val preKey = PreKey(expectedDeviceUid, keyId, encryptionKeyPair.publicKey as EncryptionPublicKey, 123456789L)
        val capabilities = arrayOf("cap1", "cap2")

        val blob = PreKeyBlobOnServer(preKey, capabilities)
        assertEquals(preKey, blob.preKey)
        assertArrayEquals(capabilities, blob.rawDeviceCapabilities)
    }

    @Test
    fun testVerifySignatureAndDecodeSuccess() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 2000L
        val serverTimestamp = 1000L

        // 1. Build preKeyList
        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)

        // 2. Build dictionary with capabilities
        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val capabilities = arrayOf("feat1", "feat2")
        dict[DictionaryKey("cap")] = Encoded.of(capabilities)
        val encodedDict = Encoded.of(dict)

        // 3. Create Identity & sign
        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val signatureBytes = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDict.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        // 4. Wrap into signed prekey
        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(signatureBytes!!)
        ))

        // 5. Decode
        val decodedBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedPreKeyEncoded,
            identity,
            expectedDeviceUid,
            serverTimestamp
        )

        assertNotNull(decodedBlob)
        assertEquals(expectedDeviceUid, decodedBlob!!.preKey.deviceUid)
        assertArrayEquals(keyIdBytes, decodedBlob.preKey.keyId!!.bytes)
        assertEquals(expirationTimestamp, decodedBlob.preKey.expirationTimestamp)
        assertArrayEquals(capabilities, decodedBlob.rawDeviceCapabilities)
    }

    @Test
    fun testVerifySignatureAndDecodeSuccessWithoutCapabilities() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 2000L
        val serverTimestamp = 1000L

        // 1. Build preKeyList
        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)

        // 2. Build dictionary without capabilities
        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val encodedDict = Encoded.of(dict)

        // 3. Create Identity & sign
        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val signatureBytes = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDict.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        // 4. Wrap into signed prekey
        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(signatureBytes!!)
        ))

        // 5. Decode
        val decodedBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedPreKeyEncoded,
            identity,
            expectedDeviceUid,
            serverTimestamp
        )

        assertNotNull(decodedBlob)
        assertEquals(expectedDeviceUid, decodedBlob!!.preKey.deviceUid)
        assertNull(decodedBlob.rawDeviceCapabilities)
    }

    @Test
    fun testVerifySignatureFailure() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 2000L

        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)
        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val encodedDict = Encoded.of(dict)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        // Invalid signature bytes
        val invalidSignatureBytes = ByteArray(64) { 0 }

        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(invalidSignatureBytes)
        ))

        val decodedBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedPreKeyEncoded,
            identity,
            expectedDeviceUid,
            1000L
        )

        assertNull(decodedBlob)
    }

    @Test
    fun testInvalidStructureThrowsException() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        // Passing an Encoded object that is not a list will trigger the exception block in verifySignatureAndDecode
        val invalidEncoded = Encoded.of(ByteArray(10))

        val decodedBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
            invalidEncoded,
            identity,
            expectedDeviceUid,
            1000L
        )

        assertNull(decodedBlob)
    }

    @Test
    fun testDeviceUidMismatchAndPrekeyMissing() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val wrongDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 2000L

        // 1. Prekey list with expectedDeviceUid
        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)

        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val encodedDict = Encoded.of(dict)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val signatureBytes = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDict.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(signatureBytes!!)
        ))

        // Decode with wrongDeviceUid -> UID mismatch -> returns null
        val decodedBlobMismatch = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedPreKeyEncoded,
            identity,
            wrongDeviceUid,
            1000L
        )
        assertNull(decodedBlobMismatch)

        // 2. Dictionary without "prk"
        val dictMissingPrk = HashMap<DictionaryKey, Encoded>()
        val encodedDictMissing = Encoded.of(dictMissingPrk)
        val signatureMissing = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDictMissing.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )
        val signedMissingEncoded = Encoded.of(arrayOf(
            encodedDictMissing,
            Encoded.of(signatureMissing!!)
        ))

        val decodedBlobMissingPrk = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedMissingEncoded,
            identity,
            expectedDeviceUid,
            1000L
        )
        assertNull(decodedBlobMissingPrk)
    }

    @Test
    fun testPreKeyAlreadyExpired() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 1000L
        val serverTimestamp = 2000L // Already expired!

        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)

        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val encodedDict = Encoded.of(dict)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val signatureBytes = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDict.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(signatureBytes!!)
        ))

        val decodedBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedPreKeyEncoded,
            identity,
            expectedDeviceUid,
            serverTimestamp
        )

        assertNull(decodedBlob)
    }

    @Test
    fun testStaticDelegatorReflection() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 2000L
        val serverTimestamp = 1000L

        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)
        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val encodedDict = Encoded.of(dict)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val signatureBytes = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDict.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(signatureBytes!!)
        ))

        // Get static method on outer class PreKeyBlobOnServer
        val method = PreKeyBlobOnServer::class.java.getMethod(
            "verifySignatureAndDecode",
            Encoded::class.java,
            Identity::class.java,
            UID::class.java,
            java.lang.Long::class.java
        )
        val result = method.invoke(null, signedPreKeyEncoded, identity, expectedDeviceUid, serverTimestamp) as? PreKeyBlobOnServer
        assertNotNull(result)
        assertEquals(expectedDeviceUid, result!!.preKey.deviceUid)
    }

    @Test
    fun testNullServerTimestamp() {
        val zeroSeed = Seed(ByteArray(32))
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(zeroSeed)
        val expectedDeviceUid = UID(prng)
        val keyIdBytes = ByteArray(32) { 1.toByte() }
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val compactPublicKey = (encryptionKeyPair.publicKey as EncryptionPublicKey).compactKey
        val expirationTimestamp = 2000L

        val preKeyList = arrayOf(
            Encoded.of(keyIdBytes),
            Encoded.of(compactPublicKey),
            Encoded.of(expectedDeviceUid),
            Encoded.of(expirationTimestamp)
        )
        val encodedPreKey = Encoded.of(preKeyList)
        val dict = HashMap<DictionaryKey, Encoded>()
        dict[DictionaryKey("prk")] = encodedPreKey
        val encodedDict = Encoded.of(dict)

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey
        )

        val signatureBytes = Signature.sign(
            Constants.SignatureContext.DEVICE_PRE_KEY,
            encodedDict.bytes,
            serverAuthKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        val signedPreKeyEncoded = Encoded.of(arrayOf(
            encodedDict,
            Encoded.of(signatureBytes!!)
        ))

        // Decode with null serverTimestamp -> returns null
        val decodedBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
            signedPreKeyEncoded,
            identity,
            expectedDeviceUid,
            null
        )
        assertNull(decodedBlob)
    }
}
