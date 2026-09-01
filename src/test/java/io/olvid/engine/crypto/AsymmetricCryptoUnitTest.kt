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

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.MappingIterator
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.containers.CiphertextAndKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesMDCKeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaPublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignaturePublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.net.URL
import java.util.Arrays

class AsymmetricCryptoUnitTest {

    class TestVector {
        var plaintext: String? = null
        var ciphertext: String? = null
        var seed: String? = null
        var algorithmImplementationByteIdValue: Int = 0
        var encodedPublicKey: String? = null
        var encodedRecipientPrivateKey: String? = null
        var encodedPrivateKey: String? = null
        var challenge: String? = null
        var response: String? = null
    }

    companion object {
        private fun fromHex(hex: String): ByteArray {
            val len = hex.length
            val data = ByteArray(len / 2)
            for (i in 0 until len step 2) {
                data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            }
            return data
        }
    }

    @Before
    fun setUp() {
        Logger.setOutputLogLevel(Logger.DEBUG)
    }

    @Test
    @Throws(Exception::class)
    fun test_ServerAuthentication() {
        run {
            val mapper = ObjectMapper()
            val jsonURL: URL = javaClass.classLoader.getResource("TestVectorsServerAuthentication.json")!!
            val parser: JsonParser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            var i =0
            while (iter.hasNext() && i < 50) {
                i++
                val vec = iter.next() as TestVector
                val prng: PRNGService = PRNGServiceHmacSHA256.instance
                val pk = Encoded(fromHex(vec.encodedPublicKey!!)).decodePublicKey() as ServerAuthenticationECSdsaPublicKey
                val sk = Encoded(fromHex(vec.encodedPrivateKey!!)).decodePrivateKey() as ServerAuthenticationECSdsaPrivateKey
                val challenge = fromHex(vec.challenge!!)
                val expectedResponse = fromHex(vec.response!!)
                val serverAuthentication: ServerAuthentication = Suite.getServerAuthentication(pk)!!
                prng.reseed(Seed(fromHex(vec.seed!!)))
                val response = serverAuthentication.solveChallenge(challenge, sk, pk, prng)
                assertArrayEquals(response, expectedResponse)

                val signature = Arrays.copyOfRange(response, Constants.SIGNATURE_PADDING_LENGTH, response.size)
                val authPrefix = Constants.SERVER_AUTHENTICATION_SIGNATURE_CHALLENGE_PREFIX
                val formattedChallenge = ByteArray(authPrefix.size + challenge.size + Constants.SIGNATURE_PADDING_LENGTH)
                System.arraycopy(authPrefix, 0, formattedChallenge, 0, authPrefix.size)
                System.arraycopy(challenge, 0, formattedChallenge, authPrefix.size, challenge.size)
                System.arraycopy(response, 0, formattedChallenge, authPrefix.size + challenge.size, Constants.SIGNATURE_PADDING_LENGTH)
                val signaturePublicKey: SignaturePublicKey = pk.signaturePublicKey
                val signatureImplem: Signature = Suite.getSignature(signaturePublicKey)!!
                assertTrue(signatureImplem.verify(signaturePublicKey, formattedChallenge, signature))
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_kemDecrypt() {
        val prng: PRNGService = Suite.getDefaultPRNGService(0)
        for (i in 0 until 10) {
            val pair: EncryptionEciesMDCKeyPair = EncryptionEciesMDCKeyPair.generate(prng)!!
            val kem = KemEcies256Kem512MDC()
            for (j in 0 until 100) {
                val ciphertextAndKey: CiphertextAndKey = kem.encrypt(pair.publicKey as EncryptionPublicKey, prng)!!
                val dec: AuthEncKey = kem.decrypt(pair.privateKey as EncryptionPrivateKey, ciphertextAndKey.ciphertext!!.bytes)!!
                assertEquals(ciphertextAndKey.key, dec)
            }
        }
    }
}
