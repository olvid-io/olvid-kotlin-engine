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

package io.olvid.engine.crypto

import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.Constants.SignatureContext
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncAES256ThenSHA256Key
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The primitives must return their failure value (⊥ / false / null),
 * or throw their checked failure exception, on inputs that are too short. They must never let an unchecked
 * exception (index out of bounds, illegal argument...) escape: those are not caught on the reception path
 * and turn a malformed message into a denial of service.
 */
class ShortInputCryptoTest {
    private lateinit var prng: PRNGService

    @Before
    fun setUp() {
        prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))
    }

    @Test
    fun authEncDecrypt_shortOrForgedCiphertext_throwsDecryptionException() {
        val authEnc = Suite.getDefaultAuthEnc(0)
        val key = authEnc.generateKey(prng)

        for (len in 0..64) {
            assertThrows("length $len", DecryptionException::class.java) {
                authEnc.decrypt(key, EncryptedBytes(prng.bytes(len)))
            }
        }

        val plaintext = "plaintext".toByteArray()
        assertArrayEquals(plaintext, authEnc.decrypt(key, authEnc.encrypt(key, plaintext, prng)))
    }

    @Test
    fun symEncDecrypt_ciphertextShorterThanIv_throwsDecryptionException() {
        val key = Suite.getDefaultAuthEnc(0).generateKey(prng) as AuthEncAES256ThenSHA256Key
        val symEnc = SymEncCtrAES256(key.encKey)

        for (len in 0 until 8) {
            assertThrows("length $len", DecryptionException::class.java) {
                symEnc.decrypt(EncryptedBytes(prng.bytes(len)))
            }
        }
    }

    @Test
    fun publicKeyDecrypt_shortOrForgedCiphertext_throwsDecryptionException() {
        for (algo in listOf(
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256,
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256,
        )) {
            val keyPair = Suite.generateEncryptionKeyPair(algo, prng)!!
            val publicKey = keyPair.publicKey as EncryptionPublicKey
            val privateKey = keyPair.privateKey as EncryptionPrivateKey
            val pke = Suite.getPublicKeyEncryption(publicKey)!!

            for (len in 0..96) {
                assertThrows("algo $algo, length $len", DecryptionException::class.java) {
                    pke.decrypt(privateKey, EncryptedBytes(prng.bytes(len)))
                }
            }
            // a valid KEM part followed by a too short DEM part
            val kemOnly = pke.encrypt(publicKey, ByteArray(0), prng)!!.getBytes().copyOfRange(0, 40)
            assertThrows("algo $algo, truncated", DecryptionException::class.java) {
                pke.decrypt(privateKey, EncryptedBytes(kemOnly))
            }

            val plaintext = "plaintext".toByteArray()
            assertArrayEquals(plaintext, pke.decrypt(privateKey, pke.encrypt(publicKey, plaintext, prng)))
        }
    }

    @Test
    fun signatureVerify_truncatedSignature_returnsFalse() {
        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val identity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )
        val signaturePrivateKey = (serverAuthKeyPair.privateKey as ServerAuthenticationPrivateKey).signaturePrivateKey
        val context = SignatureContext.GROUP_BLOB
        val block = prng.bytes(40)
        val uid = UID(prng.bytes(UID.UID_LENGTH))
        val groupIdentifier = GroupV2.Identifier(uid, "test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)

        val valid = Signature.sign(context, block, signaturePrivateKey, prng)!!
        assertTrue(Signature.verify(context, block, identity, valid))

        for (len in 0 until valid.size) {
            val truncated = valid.copyOf(len)
            assertFalse("block, length $len", Signature.verify(context, block, identity, truncated))
            assertFalse("identities, length $len", Signature.verify(context, arrayOf(identity), identity, truncated))
            assertFalse("device uids, length $len", Signature.verify(context, uid, uid, identity, identity, identity, truncated))
            assertFalse("group, length $len", Signature.verify(context, groupIdentifier, block, identity, identity, truncated))
        }
    }

    @Test
    fun commitmentOpen_decommitmentShorterThanRandomPart_returnsNull() {
        val commitment = Suite.getDefaultCommitment(0)
        val tag = prng.bytes(16)

        // the peer chooses both the commitment and the decommitment, so it can make the hash match
        for (len in 0 until CommitmentWithSHA256.COMMITMENT_RANDOM_LENGTH) {
            val decommitment = prng.bytes(len)
            val matchingCommitment = HashSHA256().digest(tag + decommitment)
            assertNull("length $len", commitment.open(tag, matchingCommitment, decommitment))
        }

        val value = prng.bytes(20)
        val output = commitment.commit(tag, value, prng)
        assertArrayEquals(value, commitment.open(tag, output.commitment, output.decommitment))
    }
}
