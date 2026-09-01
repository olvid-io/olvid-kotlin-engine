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

import io.olvid.engine.crypto.EdwardCurve
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.PointNotOnCurveException
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger

class EdwardCurvePointTest {

    @Test
    fun testValidPointConstructorAndGetters() {
        val curve = Suite.getCurve(EdwardCurve.CURVE_25519)
        assertNotNull(curve)
        assertNotNull(curve.G)

        val gX = curve.G!!.X
        val gY = curve.G!!.Y
        assertNotNull(gX)

        // Test valid point construction
        val point = EdwardCurvePoint(gX!!, gY, curve)
        assertEquals(gX, point.X)
        assertEquals(gY, point.Y)
        assertEquals(curve, point.curve)
    }

    @Test
    fun testInvalidPointConstructorThrows() {
        val curve = Suite.getCurve(EdwardCurve.CURVE_25519)
        assertNotNull(curve.G)
        val gX = curve.G!!.X
        val gY = curve.G!!.Y
        assertNotNull(gX)

        val invalidX = gX!!.add(BigInteger.ONE)

        try {
            EdwardCurvePoint(invalidX, gY, curve)
            fail("Expected PointNotOnCurveException")
        } catch (_: PointNotOnCurveException) {
            // Expected
        }
    }

    @Test
    fun testNoCheckFactory() {
        val curve = Suite.getCurve(EdwardCurve.CURVE_25519)
        assertNotNull(curve.G)
        val gX = curve.G!!.X
        val gY = curve.G!!.Y
        assertNotNull(gX)

        // Invalid point coordinates should succeed with noCheckFactory
        val invalidX = gX!!.add(BigInteger.ONE)
        val point = EdwardCurvePoint.noCheckFactory(invalidX, gY, curve)
        assertEquals(invalidX, point.X)
        assertEquals(gY, point.Y)

        // Null X should also succeed
        val nullPoint = EdwardCurvePoint.noCheckFactory(null, gY, curve)
        assertNull(nullPoint.X)
        assertEquals(gY, nullPoint.Y)
    }

    @Test
    fun testIsLowOrderPoint() {
        val curve = Suite.getCurve(EdwardCurve.CURVE_25519)
        assertNotNull(curve.G)

        // G is not a low-order point (its order is a very large prime or small cofactor multiple)
        assertFalse(curve.G!!.isLowOrderPoint())

        // Test with X = null
        val nullXPoint = EdwardCurvePoint.noCheckFactory(null, curve.G!!.Y, curve)
        // This should run the else branch in isLowOrderPoint
        val isLowOrder = nullXPoint.isLowOrderPoint()
        // We just verify it executes without error. Whether G.Y is low order depends on the curve math, but it executes the else block.
    }

    @Test
    fun testEquals() {
        val curve = Suite.getCurve(EdwardCurve.CURVE_25519)
        assertNotNull(curve.G)
        val gX = curve.G!!.X
        val gY = curve.G!!.Y
        assertNotNull(gX)

        val p1 = EdwardCurvePoint(gX!!, gY, curve)
        val p2 = EdwardCurvePoint(gX, gY, curve)
        val p3 = EdwardCurvePoint.noCheckFactory(gX.add(BigInteger.ONE), gY, curve)
        val p4 = EdwardCurvePoint.noCheckFactory(null, gY, curve)
        val p5 = EdwardCurvePoint.noCheckFactory(null, gY, curve)
        val p6 = EdwardCurvePoint.noCheckFactory(gX, gY.add(BigInteger.ONE), curve)

        // Reflexive
        assertEquals(p1, p1)

        // Symmetric
        assertEquals(p1, p2)
        assertEquals(p2, p1)

        // Different X
        assertNotEquals(p1, p3)

        // Different Y
        assertNotEquals(p1, p6)

        // One has null X, other has non-null X
        assertNotEquals(p1, p4)
        assertNotEquals(p4, p1)

        // Both have null X
        assertEquals(p4, p5)

        // Different object type
        assertNotEquals(p1, "not a point")

        // Null
        assertNotEquals(p1, null)
    }
}
