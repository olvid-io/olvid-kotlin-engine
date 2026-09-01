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

import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.CryptographicKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesMDCKeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.KeyPair
import io.olvid.engine.datatypes.key.asymmetric.PrivateKey
import io.olvid.engine.datatypes.key.asymmetric.PublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaMDCKeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignaturePublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import java.security.InvalidParameterException

object Suite {
    const val LATEST_VERSION: Int = 0
    const val MINIMUM_ACCEPTABLE_VERSION: Int = 0

    @JvmStatic
    fun getAuthEnc(authEncName: String): AuthEnc? {
        when (authEncName) {
            AuthEnc.CTR_AES256_THEN_HMAC_SHA256 -> return AuthEncAES256ThenSHA256()
            else -> return null
        }
    }

    @JvmStatic
    fun getDefaultAuthEnc(obliviousEngineVersion: Int): AuthEnc {
        return getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!
    }

    @JvmStatic
    fun getHash(hashName: String): Hash {
        when (hashName) {
            Hash.SHA512 -> return HashSHA512()
            Hash.SHA256 -> return HashSHA256()
            else -> return HashSHA256()
        }
    }

    @Throws(InvalidParameterException::class)
    @JvmStatic
    fun getPRNG(prngName: String, seed: Seed): PRNG {
        when (prngName) {
            PRNG.PRNG_HMAC_SHA256 -> return PRNGHmacSHA256(seed)
            else -> return PRNGHmacSHA256(seed)
        }
    }

    @JvmStatic
    fun getDefaultPRNG(obliviousEngineVersion: Int, seed: Seed): PRNG {
        return getPRNG(PRNG.PRNG_HMAC_SHA256, seed)
    }

    @JvmStatic
    fun getPRNGService(prngName: String): PRNGService {
        when (prngName) {
            PRNG.PRNG_HMAC_SHA256 -> return PRNGServiceHmacSHA256.instance
            else -> return PRNGServiceHmacSHA256.instance
        }
    }

    @JvmStatic
    fun getCurve(curveName: String): EdwardCurve {
        when (curveName) {
            EdwardCurve.CURVE_25519 -> return Curve25519.instance
            EdwardCurve.MDC -> return MDC.instance
            else -> return MDC.instance
        }
    }

    @JvmStatic
    fun getKDF(kdfName: String): KDF {
        when (kdfName) {
            KDF.KDF_SHA256 -> return KDFSha256()
            else -> return KDFSha256()
        }
    }

    @JvmStatic
    fun getPublicKeyEncryption(key: CryptographicKey?): PublicKeyEncryption? {
        if (key !is PublicKey && key !is PrivateKey) {
            return null
        }
        if (key.algorithmClass != CryptographicKey.ALGO_CLASS_PUBLIC_KEY_ENCRYPTION) {
            return null
        }
        when (key.algorithmImplementation) {
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 -> return PublicKeyEncryptionEciesMDC()
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 -> return PublicKeyEncryptionEciesCurve25519()
            else -> return null
        }
    }

    @JvmStatic
    fun generateServerAuthenticationKeyPair(
        serverAuthenticationAlgoImplByte: Byte?,
        prng: PRNGService
    ): KeyPair? {
        var serverAuthenticationAlgoImplByte = serverAuthenticationAlgoImplByte
        if (serverAuthenticationAlgoImplByte == null) {
            serverAuthenticationAlgoImplByte =
                getDefaultServerAuthenticationAlgoImplByte(LATEST_VERSION)
        }
        when (serverAuthenticationAlgoImplByte) {
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC -> return ServerAuthenticationECSdsaMDCKeyPair.generate(
                prng
            )

            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 -> return ServerAuthenticationECSdsaCurve25519KeyPair.generate(
                prng
            )
        }
        return null
    }

    private fun getDefaultServerAuthenticationAlgoImplByte(engineVersion: Int): Byte {
        when (engineVersion) {
            else -> return ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC
        }
    }


    @JvmStatic
    fun generateEncryptionKeyPair(encryptionAlgoImplByte: Byte?, prng: PRNGService): KeyPair? {
        var encryptionAlgoImplByte = encryptionAlgoImplByte
        if (encryptionAlgoImplByte == null) {
            encryptionAlgoImplByte = getDefaultEncryptionAlgoImplByte(LATEST_VERSION)
        }
        when (encryptionAlgoImplByte) {
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 -> return EncryptionEciesMDCKeyPair.generate(
                prng
            )

            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 -> return EncryptionEciesCurve25519KeyPair.generate(
                prng
            )
        }
        return null
    }

    private fun getDefaultEncryptionAlgoImplByte(engineVersion: Int): Byte {
        when (engineVersion) {
            else -> return EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256
        }
    }

    @JvmStatic
    fun getServerAuthentication(key: CryptographicKey?): ServerAuthentication? {
        if (key !is PublicKey && key !is PrivateKey) {
            return null
        }
        if (key.algorithmClass != CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION) {
            return null
        }
        when (key.algorithmImplementation) {
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC -> return ServerAuthenticationECSdsaMDC()
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 -> return ServerAuthenticationECSdsaCurve25519()
            else -> return null
        }
    }

    @JvmStatic
    fun getSignature(key: CryptographicKey?): Signature? {
        if (key !is PublicKey && key !is PrivateKey) {
            return null
        }
        if (key.algorithmClass != CryptographicKey.ALGO_CLASS_SIGNATURE) {
            return null
        }
        when (key.algorithmImplementation) {
            SignaturePublicKey.ALGO_IMPL_EC_SDSA_MDC -> return SignatureECSdsaMDC()
            SignaturePublicKey.ALGO_IMPL_EC_SDSA_CURVE25519 -> return SignatureECSdsaCurve25519()
            else -> return null
        }
    }

    @JvmStatic
    fun getAuthEnc(key: CryptographicKey?): AuthEnc? {
        if (key !is SymmetricKey) {
            return null
        }
        if (key.algorithmClass != CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION) {
            return null
        }
        when (key.algorithmImplementation) {
            AuthEncKey.ALGO_IMPL_AES256_THEN_SHA256 -> return AuthEncAES256ThenSHA256()
            else -> return null
        }
    }

    @JvmStatic
    fun getMAC(key: CryptographicKey?): MAC? {
        if (key !is SymmetricKey) {
            return null
        }
        if (key.algorithmClass != CryptographicKey.ALGO_CLASS_MAC) {
            return null
        }
        when (key.algorithmImplementation) {
            MACKey.ALGO_IMPL_HMAC_SHA256 -> return MACHmacSha256()
            else -> return null
        }
    }

    @JvmStatic
    fun getMAC(macName: String): MAC? {
        when (macName) {
            MAC.HMAC_SHA256 -> return MACHmacSha256()
            else -> return null
        }
    }

    @JvmStatic
    fun getDefaultKDF(obliviousEngineVersion: Int): KDF {
        return KDFSha256()
    }

    @JvmStatic
    fun getDefaultPRNGService(obliviousEngineVersion: Int): PRNGService {
        return getPRNGService(PRNG.PRNG_HMAC_SHA256)
    }

    @JvmStatic
    fun getDefaultCommitment(obliviousEngineVersion: Int): Commitment {
        return CommitmentWithSHA256()
    }

    @JvmStatic
    fun getDefaultMAC(obliviousEngineVersion: Int): MAC {
        return MACHmacSha256()
    }
}
