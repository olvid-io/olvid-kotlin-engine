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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaMDCKeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignaturePublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [Suite] and algorithm-name/ALGO_IMPL byte constants.
 *
 * These tests pin all load-bearing wire contracts:
 *  - Algorithm-name string constants (wire-format, stored in DB encoded keys and JSON)
 *  - ALGO_IMPL byte constants (wire-format, embedded in serialized key bytes)
 *  - Suite.LATEST_VERSION / MINIMUM_ACCEPTABLE_VERSION integers
 *  - Suite dispatch-table contracts (algorithm-name/key → implementation class)
 *  - Suite default-algorithm factories (version 0 → expected implementation)
 *  - Suite.generateEncryptionKeyPair / generateServerAuthenticationKeyPair selection
 *  - Suite.getPublicKeyEncryption / getServerAuthentication / getSignature / getAuthEnc(key) / getMAC(key)
 *  - Suite.getDefaultCommitment returns CommitmentWithSHA256
 */
class SuiteAndAlgorithmConstantsTest {

    private lateinit var prng: PRNG
    private lateinit var prngService: PRNGService

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

        val seed = Seed(ByteArray(Seed.MIN_SEED_LENGTH) { it.toByte() })
        prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
        prngService = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)
    }

    // ─── Group 1: Algorithm-name string constants (wire-format / DB-persisted) ──
    //
    // These strings appear verbatim in JSON key serializations and DB columns.
    // A migration that renames a constant's value (not just its Kotlin identifier)
    // would silently break deserialization of existing stored keys.

    @Test
    fun testAuthEncCtrAes256ThenHmacSha256_exactWireString() {
        assertEquals("ctr-aes-256_then_hmac_sha-256", AuthEnc.CTR_AES256_THEN_HMAC_SHA256)
    }

    @Test
    fun testHashSha256_exactWireString() {
        assertEquals("sha-256", Hash.SHA256)
    }

    @Test
    fun testHashSha512_exactWireString() {
        assertEquals("sha-512", Hash.SHA512)
    }

    @Test
    fun testMacHmacSha256_exactWireString() {
        assertEquals("hmac_sha-256", MAC.HMAC_SHA256)
    }

    @Test
    fun testKdfSha256_exactWireString() {
        assertEquals("kdf_sha-256", KDF.KDF_SHA256)
    }

    @Test
    fun testPrngHmacSha256_exactWireString() {
        assertEquals("prng_hmac_sha-256", PRNG.PRNG_HMAC_SHA256)
    }

    @Test
    fun testEdwardCurveMdc_exactWireString() {
        assertEquals("MDC", EdwardCurve.MDC)
    }

    @Test
    fun testEdwardCurveCurve25519_exactWireString() {
        assertEquals("Curve_25519", EdwardCurve.CURVE_25519)
    }

    // ─── Group 2: ALGO_IMPL byte constants (wire-format key identification) ──────
    //
    // These bytes are the first byte of compact serialized key representations and
    // appear in DB-stored key blobs. Changing any value breaks deserialization of
    // all existing keys persisted with the old byte.

    // EncryptionPublicKey
    @Test
    fun testEncryptionPublicKey_algoImplMdc_isExactly0x00() {
        assertEquals(0x00.toByte(), EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256)
    }

    @Test
    fun testEncryptionPublicKey_algoImplCurve25519_isExactly0x01() {
        assertEquals(0x01.toByte(), EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256)
    }

    // ServerAuthenticationPublicKey
    @Test
    fun testServerAuthenticationPublicKey_algoImplEcSdsaMdc_isExactly0x00() {
        assertEquals(0x00.toByte(), ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC)
    }

    @Test
    fun testServerAuthenticationPublicKey_algoImplEcSdsaCurve25519_isExactly0x01() {
        assertEquals(0x01.toByte(), ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519)
    }

    // SignaturePublicKey
    @Test
    fun testSignaturePublicKey_algoImplEcSdsaMdc_isExactly0x00() {
        assertEquals(0x00.toByte(), SignaturePublicKey.ALGO_IMPL_EC_SDSA_MDC)
    }

    @Test
    fun testSignaturePublicKey_algoImplEcSdsaCurve25519_isExactly0x01() {
        assertEquals(0x01.toByte(), SignaturePublicKey.ALGO_IMPL_EC_SDSA_CURVE25519)
    }

    // AuthEncKey (symmetric)
    @Test
    fun testAuthEncKey_algoImplAes256ThenSha256_isExactly0x00() {
        assertEquals(0x00.toByte(), AuthEncKey.ALGO_IMPL_AES256_THEN_SHA256)
    }

    // MACKey (symmetric)
    @Test
    fun testMacKey_algoImplHmacSha256_isExactly0x00() {
        assertEquals(0x00.toByte(), MACKey.ALGO_IMPL_HMAC_SHA256)
    }

    // ─── Group 3: Suite version constants ─────────────────────────────────────────
    //
    // LATEST_VERSION and MINIMUM_ACCEPTABLE_VERSION are used in key-pair generation
    // and protocol negotiation. Changing these values without a migration would cause
    // the engine to reject valid stored keys or produce incompatible new ones.

    @Test
    fun testSuiteLatestVersionIsExactly0() {
        assertEquals(0, Suite.LATEST_VERSION)
    }

    @Test
    fun testSuiteMinimumAcceptableVersionIsExactly0() {
        assertEquals(0, Suite.MINIMUM_ACCEPTABLE_VERSION)
    }

    // ─── Group 4: Suite.getAuthEnc(String) dispatch table ─────────────────────────

    @Test
    fun testGetAuthEncByName_ctrAes256ThenHmacSha256_returnsAuthEncAES256ThenSHA256() {
        val result = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)
        assertNotNull(result)
        assertEquals("AuthEncAES256ThenSHA256", result!!.javaClass.simpleName)
    }

    @Test
    fun testGetAuthEncByName_unknownName_returnsNull() {
        assertNull(Suite.getAuthEnc("unknown-authenc"))
    }

    // ─── Group 5: Suite.getHash(String) dispatch table ────────────────────────────
    //
    // Note: the getHash switch uses SHA256 as default, so unknown names return HashSHA256.
    // The SHA256 and SHA512 named paths are pinned here.

    @Test
    fun testGetHashByName_sha256_returnsHashSHA256() {
        val result = Suite.getHash(Hash.SHA256)
        assertEquals("HashSHA256", result.javaClass.simpleName)
    }

    @Test
    fun testGetHashByName_sha512_returnsHashSHA512() {
        val result = Suite.getHash(Hash.SHA512)
        assertEquals("HashSHA512", result.javaClass.simpleName)
    }

    @Test
    fun testGetHashByName_unknownName_fallsBackToHashSHA256() {
        // getHash has SHA256 as the default branch — unknown inputs must return HashSHA256,
        // not null. A migration that converts to null-return would break all callers.
        val result = Suite.getHash("unknown-hash")
        assertEquals("HashSHA256", result.javaClass.simpleName)
    }

    // ─── Group 6: Suite.getPRNG(String, Seed) dispatch table ──────────────────────

    @Test
    fun testGetPrngByName_prngHmacSha256_returnsPRNGHmacSHA256() {
        val seed = Seed(ByteArray(Seed.MIN_SEED_LENGTH))
        val result = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
        assertEquals("PRNGHmacSHA256", result.javaClass.simpleName)
    }

    @Test
    fun testGetPrngByName_unknownName_fallsBackToPRNGHmacSHA256() {
        // getPRNG has PRNG_HMAC_SHA256 as the default branch.
        val seed = Seed(ByteArray(Seed.MIN_SEED_LENGTH))
        val result = Suite.getPRNG("unknown-prng", seed)
        assertEquals("PRNGHmacSHA256", result.javaClass.simpleName)
    }

    // ─── Group 7: Suite.getCurve(String) dispatch table ───────────────────────────

    @Test
    fun testGetCurveByName_curve25519_returnsCurve25519() {
        val result = Suite.getCurve(EdwardCurve.CURVE_25519)
        assertEquals("Curve25519", result.javaClass.simpleName)
    }

    @Test
    fun testGetCurveByName_mdc_returnsMDC() {
        val result = Suite.getCurve(EdwardCurve.MDC)
        assertEquals("MDC", result.javaClass.simpleName)
    }

    @Test
    fun testGetCurveByName_unknownName_fallsBackToMDC() {
        // getCurve has MDC as default branch.
        val result = Suite.getCurve("unknown-curve")
        assertEquals("MDC", result.javaClass.simpleName)
    }

    // ─── Group 8: Suite.getKDF(String) dispatch table ─────────────────────────────

    @Test
    fun testGetKdfByName_kdfSha256_returnsKDFSha256() {
        val result = Suite.getKDF(KDF.KDF_SHA256)
        assertEquals("KDFSha256", result.javaClass.simpleName)
    }

    @Test
    fun testGetKdfByName_unknownName_fallsBackToKDFSha256() {
        val result = Suite.getKDF("unknown-kdf")
        assertEquals("KDFSha256", result.javaClass.simpleName)
    }

    // ─── Group 9: Suite.getMAC(String) dispatch table ─────────────────────────────

    @Test
    fun testGetMacByName_hmacSha256_returnsMACHmacSha256() {
        val result = Suite.getMAC(MAC.HMAC_SHA256)
        assertNotNull(result)
        assertEquals("MACHmacSha256", result!!.javaClass.simpleName)
    }

    @Test
    fun testGetMacByName_unknownName_returnsNull() {
        assertNull(Suite.getMAC("unknown-mac"))
    }

    // ─── Group 10: Suite default-algorithm factories ───────────────────────────────

    @Test
    fun testGetDefaultAuthEnc_version0_returnsAuthEncAES256ThenSHA256() {
        val result = Suite.getDefaultAuthEnc(0)
        assertNotNull(result)
        assertEquals("AuthEncAES256ThenSHA256", result.javaClass.simpleName)
    }

    @Test
    fun testGetDefaultPrng_version0_returnsPRNGHmacSHA256() {
        val seed = Seed(ByteArray(Seed.MIN_SEED_LENGTH))
        val result = Suite.getDefaultPRNG(0, seed)
        assertEquals("PRNGHmacSHA256", result.javaClass.simpleName)
    }

    @Test
    fun testGetDefaultPrngService_version0_returnsPRNGServiceHmacSHA256() {
        val result = Suite.getDefaultPRNGService(0)
        assertEquals("PRNGServiceHmacSHA256", result.javaClass.simpleName)
    }

    @Test
    fun testGetDefaultKdf_version0_returnsKDFSha256() {
        val result = Suite.getDefaultKDF(0)
        assertEquals("KDFSha256", result.javaClass.simpleName)
    }

    @Test
    fun testGetDefaultMac_version0_returnsMACHmacSha256() {
        val result = Suite.getDefaultMAC(0)
        assertEquals("MACHmacSha256", result.javaClass.simpleName)
    }

    @Test
    fun testGetDefaultCommitment_version0_returnsCommitmentWithSHA256() {
        val result = Suite.getDefaultCommitment(0)
        assertEquals("CommitmentWithSHA256", result.javaClass.simpleName)
    }

    // ─── Group 11: Suite.generateEncryptionKeyPair ────────────────────────────────
    //
    // null → LATEST_VERSION default → Curve25519 variant
    // explicit byte → corresponding variant

    @Test
    fun testGenerateEncryptionKeyPair_nullByte_defaultsToCurve25519Variant() {
        // getDefaultEncryptionAlgoImplByte(LATEST_VERSION=0) returns
        // ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256.
        val kp = Suite.generateEncryptionKeyPair(null, prngService)
        assertNotNull(kp)
        assertEquals(
            "EncryptionEciesCurve25519KeyPair",
            kp!!.javaClass.simpleName,
        )
    }

    @Test
    fun testGenerateEncryptionKeyPair_mdcByte_returnsMdcVariant() {
        val kp = Suite.generateEncryptionKeyPair(
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256,
            prngService,
        )
        assertNotNull(kp)
        assertEquals("EncryptionEciesMDCKeyPair", kp!!.javaClass.simpleName)
    }

    @Test
    fun testGenerateEncryptionKeyPair_curve25519Byte_returnsCurve25519Variant() {
        val kp = Suite.generateEncryptionKeyPair(
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256,
            prngService,
        )
        assertNotNull(kp)
        assertEquals("EncryptionEciesCurve25519KeyPair", kp!!.javaClass.simpleName)
    }

    @Test
    fun testGenerateEncryptionKeyPair_unknownByte_returnsNull() {
        val kp = Suite.generateEncryptionKeyPair(0x7F.toByte(), prngService)
        assertNull(kp)
    }

    // ─── Group 12: Suite.generateServerAuthenticationKeyPair ──────────────────────
    //
    // null → getDefaultServerAuthenticationAlgoImplByte(0) → EC_SDSA_MDC

    @Test
    fun testGenerateServerAuthenticationKeyPair_nullByte_defaultsToMdcVariant() {
        val kp = Suite.generateServerAuthenticationKeyPair(null, prngService)
        assertNotNull(kp)
        assertEquals("ServerAuthenticationECSdsaMDCKeyPair", kp!!.javaClass.simpleName)
    }

    @Test
    fun testGenerateServerAuthenticationKeyPair_mdcByte_returnsMdcVariant() {
        val kp = Suite.generateServerAuthenticationKeyPair(
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC,
            prngService,
        )
        assertNotNull(kp)
        assertEquals("ServerAuthenticationECSdsaMDCKeyPair", kp!!.javaClass.simpleName)
    }

    @Test
    fun testGenerateServerAuthenticationKeyPair_curve25519Byte_returnsCurve25519Variant() {
        val kp = Suite.generateServerAuthenticationKeyPair(
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519,
            prngService,
        )
        assertNotNull(kp)
        assertEquals("ServerAuthenticationECSdsaCurve25519KeyPair", kp!!.javaClass.simpleName)
    }

    @Test
    fun testGenerateServerAuthenticationKeyPair_unknownByte_returnsNull() {
        val kp = Suite.generateServerAuthenticationKeyPair(0x7F.toByte(), prngService)
        assertNull(kp)
    }

    // ─── Group 13: Suite.getPublicKeyEncryption(CryptographicKey) dispatch ────────
    //
    // Filters on ALGO_CLASS_PUBLIC_KEY_ENCRYPTION; wrong class → null.

    @Test
    fun testGetPublicKeyEncryption_curve25519PublicKey_returnsEciesCurve25519() {
        val kp = Suite.generateEncryptionKeyPair(
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256,
            prngService,
        )
        val enc = Suite.getPublicKeyEncryption(kp!!.publicKey)
        assertNotNull(enc)
        assertEquals("PublicKeyEncryptionEciesCurve25519", enc!!.javaClass.simpleName)
    }

    @Test
    fun testGetPublicKeyEncryption_mdcPublicKey_returnsEciesMDC() {
        val kp = Suite.generateEncryptionKeyPair(
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256,
            prngService,
        )
        val enc = Suite.getPublicKeyEncryption(kp!!.publicKey)
        assertNotNull(enc)
        assertEquals("PublicKeyEncryptionEciesMDC", enc!!.javaClass.simpleName)
    }

    @Test
    fun testGetPublicKeyEncryption_serverAuthKey_wrongClass_returnsNull() {
        // A ServerAuthentication key has ALGO_CLASS_SERVER_AUTHENTICATION, not
        // ALGO_CLASS_PUBLIC_KEY_ENCRYPTION, so the class guard must return null.
        val kp = Suite.generateServerAuthenticationKeyPair(null, prngService)
        assertNull(Suite.getPublicKeyEncryption(kp!!.publicKey))
    }

    // ─── Group 14: Suite.getServerAuthentication(CryptographicKey) dispatch ───────

    @Test
    fun testGetServerAuthentication_mdcPublicKey_returnsEcSdsaMDC() {
        val kp = Suite.generateServerAuthenticationKeyPair(
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC,
            prngService,
        )
        val sa = Suite.getServerAuthentication(kp!!.publicKey)
        assertNotNull(sa)
        assertEquals("ServerAuthenticationECSdsaMDC", sa!!.javaClass.simpleName)
    }

    @Test
    fun testGetServerAuthentication_curve25519PublicKey_returnsEcSdsaCurve25519() {
        val kp = Suite.generateServerAuthenticationKeyPair(
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519,
            prngService,
        )
        val sa = Suite.getServerAuthentication(kp!!.publicKey)
        assertNotNull(sa)
        assertEquals("ServerAuthenticationECSdsaCurve25519", sa!!.javaClass.simpleName)
    }

    @Test
    fun testGetServerAuthentication_encryptionKey_wrongClass_returnsNull() {
        val kp = Suite.generateEncryptionKeyPair(null, prngService)
        assertNull(Suite.getServerAuthentication(kp!!.publicKey))
    }

    // ─── Group 15: Suite.getSignature(CryptographicKey) dispatch ──────────────────
    //
    // Signature keys are generated via server authentication MDC keypair's inner signature key.

    @Test
    fun testGetSignature_mdcSignaturePrivateKey_returnsSignatureECSdsaMDC() {
        val kp = Suite.generateServerAuthenticationKeyPair(
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC,
            prngService,
        )
        // The server auth MDC private key contains a signature private key.
        // getPrivateKey() is overridden in ServerAuthenticationECSdsaMDCKeyPair to return
        // ServerAuthenticationECSdsaMDCPrivateKey, which extends ServerAuthenticationECSdsaPrivateKey
        // and exposes the inner signaturePrivateKey property.
        val mdcKeyPair = kp as ServerAuthenticationECSdsaMDCKeyPair
        val signaturePrivateKey = mdcKeyPair.getPrivateKey().signaturePrivateKey
        val sig = Suite.getSignature(signaturePrivateKey)
        assertNotNull(sig)
        assertEquals("SignatureECSdsaMDC", sig!!.javaClass.simpleName)
    }

    @Test
    fun testGetSignature_encryptionKey_wrongClass_returnsNull() {
        val kp = Suite.generateEncryptionKeyPair(null, prngService)
        assertNull(Suite.getSignature(kp!!.publicKey))
    }

    // ─── Group 16: Suite.getAuthEnc(CryptographicKey) dispatch ───────────────────
    //
    // Filters on ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION.

    @Test
    fun testGetAuthEncByKey_aes256ThenSha256Key_returnsAuthEncAES256ThenSHA256() {
        val authEncImpl = Suite.getDefaultAuthEnc(0)
        val authEncKey = authEncImpl.generateKey(prng)
        val result = Suite.getAuthEnc(authEncKey)
        assertNotNull(result)
        assertEquals("AuthEncAES256ThenSHA256", result!!.javaClass.simpleName)
    }

    @Test
    fun testGetAuthEncByKey_macKey_wrongClass_returnsNull() {
        val macImpl = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = macImpl.generateKey(prng)
        assertNull(Suite.getAuthEnc(macKey))
    }

    // ─── Group 17: Suite.getMAC(CryptographicKey) dispatch ───────────────────────
    //
    // Filters on ALGO_CLASS_MAC.

    @Test
    fun testGetMacByKey_hmacSha256Key_returnsMACHmacSha256() {
        val macImpl = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = macImpl.generateKey(prng)
        val result = Suite.getMAC(macKey)
        assertNotNull(result)
        assertEquals("MACHmacSha256", result!!.javaClass.simpleName)
    }

    @Test
    fun testGetMacByKey_authEncKey_wrongClass_returnsNull() {
        val authEncImpl = Suite.getDefaultAuthEnc(0)
        val authEncKey = authEncImpl.generateKey(prng)
        assertNull(Suite.getMAC(authEncKey))
    }

    // ─── Group 18: Suite.getPRNGService(String) dispatch ──────────────────────────

    @Test
    fun testGetPrngService_prngHmacSha256_returnsPRNGServiceHmacSHA256() {
        val result = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)
        assertEquals("PRNGServiceHmacSHA256", result.javaClass.simpleName)
    }

    @Test
    fun testGetPrngService_unknownName_fallsBackToPRNGServiceHmacSHA256() {
        val result = Suite.getPRNGService("unknown-prng-service")
        assertEquals("PRNGServiceHmacSHA256", result.javaClass.simpleName)
    }
}
