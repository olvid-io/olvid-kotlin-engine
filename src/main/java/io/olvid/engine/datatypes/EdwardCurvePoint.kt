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
import io.olvid.engine.crypto.exceptions.PointNotOnCurveException
import java.math.BigInteger

class EdwardCurvePoint {
    @JvmField val X: BigInteger?
    @JvmField val Y: BigInteger
    @JvmField val curve: EdwardCurve

    @Throws(PointNotOnCurveException::class)
    constructor(X: BigInteger, Y: BigInteger, curve: EdwardCurve) {
        this.X = X
        this.Y = Y
        this.curve = curve
        val x2 = X.multiply(X).mod(curve.p)
        val y2 = Y.multiply(Y).mod(curve.p)
        if (x2.add(y2).mod(curve.p) != BigInteger.ONE.add(curve.d!!.multiply(x2).multiply(y2)).mod(curve.p)) {
            throw PointNotOnCurveException()
        }
    }

    private constructor(X: BigInteger?, Y: BigInteger, curve: EdwardCurve, noCheck: Boolean) {
        this.X = X
        this.Y = Y
        this.curve = curve
    }

    fun isLowOrderPoint(): Boolean {
        val currentX = X
        return if (currentX != null) {
            curve.scalarMultiplicationWithX(curve.nu!!, this).Y == BigInteger.ONE
        } else {
            curve.scalarMultiplication(curve.nu!!, Y) == BigInteger.ONE
        }
    }

    override fun equals(other: Any?): Boolean {
        if (other is EdwardCurvePoint) {
            return X == other.X && Y == other.Y
        }
        return false
    }

    companion object {
        @JvmStatic
        fun noCheckFactory(X: BigInteger?, Y: BigInteger, curve: EdwardCurve): EdwardCurvePoint {
            return EdwardCurvePoint(X, Y, curve, true)
        }
    }
}
