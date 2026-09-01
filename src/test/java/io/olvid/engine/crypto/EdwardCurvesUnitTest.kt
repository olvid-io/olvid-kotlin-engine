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
import io.olvid.engine.datatypes.EdwardCurvePoint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class EdwardCurvesUnitTest {

    class TestVector {
        var x: String? = null
        var x2: String? = null
        var x3: String? = null
        var x4: String? = null
        var x5: String? = null
        var y: String? = null
        var y2: String? = null
        var y3: String? = null
        var y4: String? = null
        var y5: String? = null
        var n: String? = null
        var ny: String? = null
        var a: String? = null
        var b: String? = null
    }

    val mdc: EdwardCurve = Suite.getCurve(EdwardCurve.MDC)
    val curve25519: EdwardCurve = Suite.getCurve(EdwardCurve.CURVE_25519)

    @Test
    @Throws(Exception::class)
    fun test_isOnCurve() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsIsOnCurveMDC.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), mdc)
                try {
                    EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y), mdc)
                    assertTrue(false)
                } catch (_: Exception) {}
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsIsOnCurveCurve25519.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), curve25519)
                try {
                    EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y), curve25519)
                    assertTrue(false)
                } catch (_: Exception) {}
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_xCoordiateFromY() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsIsOnCurveMDC.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val X = BigInteger(vec.x)
                val Y = BigInteger(vec.y)
                val X2 = mdc.xCoordinateFromY(Y)
                assertTrue(X == X2 || mdc.p!!.subtract(X) == X2)
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsIsOnCurveCurve25519.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val X = BigInteger(vec.x)
                val Y = BigInteger(vec.y)
                val X2 = curve25519.xCoordinateFromY(Y)
                assertTrue(X == X2 || curve25519.p!!.subtract(X) == X2)
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_scalarMultiplication() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsScalarMultiplicationMDC.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val y = BigInteger(vec.y)
                val n = BigInteger(vec.n)
                val ny = BigInteger(vec.ny)
                val ny2 = mdc.scalarMultiplication(n, y)
                assertEquals(ny, ny2)
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsScalarMultiplicationCurve25519.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val y = BigInteger(vec.y)
                val n = BigInteger(vec.n)
                val ny = BigInteger(vec.ny)
                val ny2 = curve25519.scalarMultiplication(n, y)
                assertEquals(ny, ny2)
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_pointAddition() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsPointAdditionMDC.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), mdc)
                val Q = EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y2), mdc)
                val R = EdwardCurvePoint(BigInteger(vec.x3), BigInteger(vec.y3), mdc)
                val R2 = mdc.pointAddition(P, Q)
                assertEquals(R, R2)
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsPointAdditionCurve25519.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), curve25519)
                val Q = EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y2), curve25519)
                val R = EdwardCurvePoint(BigInteger(vec.x3), BigInteger(vec.y3), curve25519)
                val R2 = curve25519.pointAddition(P, Q)
                assertEquals(R, R2)
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_scalarMultiplicationWithX() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsScalarMultiplicationWithXMDC.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val n = BigInteger(vec.n)
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), mdc)
                val Q = EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y2), mdc)
                val Q2 = mdc.scalarMultiplicationWithX(n, P)
                assertEquals(Q, Q2)
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsScalarMultiplicationWithXCurve25519.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val n = BigInteger(vec.n)
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), curve25519)
                val Q = EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y2), curve25519)
                val Q2 = curve25519.scalarMultiplicationWithX(n, P)
                assertEquals(Q, Q2)
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_mulAdd() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsMulAddMDC.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val a = BigInteger(vec.a)
                val b = BigInteger(vec.b)
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), mdc)
                var Q = EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y2), mdc)
                val R = EdwardCurvePoint(BigInteger(vec.x3), BigInteger(vec.y3), mdc)
                var list = mdc.mulAdd(a, P, b, Q)
                assertEquals(list.size, 1)
                val R2 = list[0]
                assertEquals(R, R2)
                Q = EdwardCurvePoint.noCheckFactory(null, BigInteger(vec.y2), mdc)
                val R3expected = EdwardCurvePoint(BigInteger(vec.x4), BigInteger(vec.y4), mdc)
                val R4expected = EdwardCurvePoint(BigInteger(vec.x5), BigInteger(vec.y5), mdc)
                list = mdc.mulAdd(a, P, b, Q)
                assertEquals(list.size, 2)
                val R3 = list[0]
                val R4 = list[1]
                assertTrue((R3 == R3expected && R4 == R4expected) || (R3 == R4expected && R4 == R3expected))
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader!!.getResource("TestVectorsMulAddCurve25519.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, TestVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as TestVector
                val a = BigInteger(vec.a)
                val b = BigInteger(vec.b)
                val P = EdwardCurvePoint(BigInteger(vec.x), BigInteger(vec.y), curve25519)
                var Q = EdwardCurvePoint(BigInteger(vec.x2), BigInteger(vec.y2), curve25519)
                val R = EdwardCurvePoint(BigInteger(vec.x3), BigInteger(vec.y3), curve25519)
                var list = curve25519.mulAdd(a, P, b, Q)
                assertEquals(list.size, 1)
                val R2 = list[0]
                assertEquals(R, R2)
                Q = EdwardCurvePoint.noCheckFactory(null, BigInteger(vec.y2), curve25519)
                val R3expected = EdwardCurvePoint(BigInteger(vec.x4), BigInteger(vec.y4), curve25519)
                val R4expected = EdwardCurvePoint(BigInteger(vec.x5), BigInteger(vec.y5), curve25519)
                list = curve25519.mulAdd(a, P, b, Q)
                assertEquals(list.size, 2)
                val R3 = list[0]
                val R4 = list[1]
                assertTrue((R3 == R3expected && R4 == R4expected) || (R3 == R4expected && R4 == R3expected))
            }
        }
    }
}
