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
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertEquals
import org.junit.Test

class ProofOfWorkUnitTest {
    class TestVector {
        var challenge: String? = null
        var response: String? = null
    }

    private fun fromHex(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
        }
        return data
    }

    @Test
    @Throws(Exception::class)
    fun test_solveChallenge() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsProofOfWork.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val challenge = Encoded(fromHex(vec.challenge!!))
                val expectedResponse = Encoded(fromHex(vec.response!!))
                val response = ProofOfWorkEngine.solveChallenge(challenge)
                assertEquals(response, expectedResponse)
            }
        }
    }
}
