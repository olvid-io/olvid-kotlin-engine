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

import io.olvid.engine.datatypes.EdwardCurvePoint
import io.olvid.engine.datatypes.EdwardCurvePoint.Companion.noCheckFactory
import java.math.BigInteger


abstract class EdwardCurve {
    @JvmField var p: BigInteger? = null
    @JvmField var q: BigInteger? = null
    @JvmField var d: BigInteger? = null
    @JvmField var cardinality: BigInteger? = null
    @JvmField var nu: BigInteger? = null
    @JvmField var nuInv: BigInteger? = null
    @JvmField var G: EdwardCurvePoint? = null
    @JvmField var tonelliNonQR: BigInteger? = null
    @JvmField var tonelliT: BigInteger? = null
    @JvmField var tonelliS: Int = 0
    @JvmField var byteLength: Int = 0

    // NOTE: this method only returns one of two possible x coordinates, the other one is (p-x)
    fun xCoordinateFromY(Y: BigInteger): BigInteger? {
        val Y2 = Y.multiply(Y).mod(p)
        val X2 = BigInteger.ONE.subtract(d!!.multiply(Y2)).modInverse(p)
            .multiply(BigInteger.ONE.subtract(Y2)).mod(p)
        return modSqrt(X2)
    }

    // NOTE: this method only returns one possible sqrt of x, the other one is (p-x)
    private fun modSqrt(x: BigInteger): BigInteger? {
        val pMinusOneDiv2 = p!!.shiftRight(1)
        if (x.modPow(pMinusOneDiv2, p) != BigInteger.ONE) {
            return null
        }
        if (p!!.testBit(1)) {
            return x.modPow(p!!.add(BigInteger.ONE).shiftRight(2), p)
        } else {
            val TWO = BigInteger.valueOf(2)
            var e = BigInteger.ZERO
            for (i in 1..<tonelliS) {
                if (tonelliNonQR!!.modPow(e, p).multiply(x)
                        .modPow(pMinusOneDiv2.shiftRight(i), p) != BigInteger.ONE
                ) {
                    e = e.add(TWO.pow(i))
                }
            }
            return tonelliNonQR!!.modPow(tonelliT!!.multiply(e).shiftRight(1), p).multiply(
                x.modPow(
                    tonelliT!!.add(
                        BigInteger.ONE
                    ).shiftRight(1), p
                )
            ).mod(p)
        }
    }

    fun scalarMultiplication(n: BigInteger, Y: BigInteger): BigInteger {
        var n = n
        if (n == BigInteger.ZERO || (Y == BigInteger.ONE)) {
            return BigInteger.ONE
        }
        if (Y == p!!.subtract(BigInteger.ONE)) {
            if (n.testBit(0)) {
                return p!!.subtract(BigInteger.ONE)
            } else {
                return BigInteger.ONE
            }
        }
        val TWO = BigInteger.valueOf(2)

        val c = BigInteger.ONE.subtract(d).modInverse(p)
        val uP = Y.add(BigInteger.ONE).mod(p)
        val wP = BigInteger.ONE.subtract(Y).mod(p)
        var uQ = BigInteger.ONE
        var wQ = BigInteger.ZERO
        var uR = uP
        var wR = wP

        // reduce n mod cardinality so we can loop on cardinality.bitLength()
        n = n.mod(cardinality)
        for (i in cardinality!!.bitLength() - 1 downTo 0) {
            val t1 = uQ.subtract(wQ).multiply(uR.add(wR)).mod(p)
            val t2 = uQ.add(wQ).multiply(uR.subtract(wR)).mod(p)
            val uQplusR = wP.multiply(t1.add(t2).modPow(TWO, p)).mod(p)
            val wQplusR = uP.multiply(t1.subtract(t2).modPow(TWO, p)).mod(p)
            if (n.testBit(i)) {
                val t3 = uR.add(wR).modPow(TWO, p)
                val t4 = uR.subtract(wR).modPow(TWO, p)
                val t5 = t3.subtract(t4).mod(p)
                val u2R = t3.multiply(t4).mod(p)
                val w2R = t5.multiply(t4.add(c.multiply(t5))).mod(p)
                uQ = uQplusR
                wQ = wQplusR
                uR = u2R
                wR = w2R
            } else {
                val t3 = uQ.add(wQ).modPow(TWO, p)
                val t4 = uQ.subtract(wQ).modPow(TWO, p)
                val t5 = t3.subtract(t4).mod(p)
                val u2Q = t3.multiply(t4).mod(p)
                val w2Q = t5.multiply(t4.add(c.multiply(t5))).mod(p)
                uQ = u2Q
                wQ = w2Q
                uR = uQplusR
                wR = wQplusR
            }
        }

        return uQ.subtract(wQ).multiply(uQ.add(wQ).modInverse(p)).mod(p)
    }

    fun pointAddition(P: EdwardCurvePoint, Q: EdwardCurvePoint): EdwardCurvePoint {
        val t =
            d!!.multiply(P.X).mod(p).multiply(Q.X).mod(p).multiply(P.Y).mod(p).multiply(Q.Y).mod(p)
        var z = t.add(BigInteger.ONE).modInverse(p)
        val X = z.multiply(P.X!!.multiply(Q.Y).add(P.Y.multiply(Q.X))).mod(p)
        z = BigInteger.ONE.subtract(t).modInverse(p)
        val Y = z.multiply(P.Y.multiply(Q.Y).subtract(P.X.multiply(Q.X))).mod(p)
        return noCheckFactory(X, Y, this)
    }


    fun scalarMultiplicationWithX(n: BigInteger, P: EdwardCurvePoint): EdwardCurvePoint {
        var n = n
        if (n == BigInteger.ZERO || P.Y == BigInteger.ONE) {
            return noCheckFactory(BigInteger.ZERO, BigInteger.ONE, this)
        }
        if (P.Y == p!!.subtract(BigInteger.ONE)) {
            if (n.testBit(0)) {
                return noCheckFactory(BigInteger.ZERO, p!!.subtract(BigInteger.ONE), this)
            } else {
                return noCheckFactory(BigInteger.ZERO, BigInteger.ONE, this)
            }
        }
        var Q = noCheckFactory(P.X, P.Y, this)
        var R = noCheckFactory(BigInteger.ZERO, BigInteger.ONE, this)

        // reduce n mod cardinality so we can loop on cardinality.bitLength()
        n = n.mod(cardinality)
        for (i in cardinality!!.bitLength() - 1 downTo 0) {
            if (n.testBit(i)) {
                R = pointAddition(R, Q)
                Q = pointAddition(Q, Q)
            } else {
                Q = pointAddition(R, Q)
                R = pointAddition(R, R)
            }
        }
        return R
    }


    fun mulAdd(
        a: BigInteger,
        P1: EdwardCurvePoint,
        b: BigInteger,
        P2: EdwardCurvePoint
    ): Array<EdwardCurvePoint?> {
        val P3 = scalarMultiplicationWithX(a, P1)
        val list = ArrayList<EdwardCurvePoint?>()
        if (P2.X != null) {
            val P4 = scalarMultiplicationWithX(b, P2)
            list.add(pointAddition(P3, P4))
        } else {
            val Y4 = scalarMultiplication(b, P2.Y)
            val X4 = xCoordinateFromY(Y4)
            var P4 = noCheckFactory(X4, Y4, this)
            list.add(pointAddition(P3, P4))
            P4 = noCheckFactory(p!!.subtract(X4), Y4, this)
            list.add(pointAddition(P3, P4))
        }
        return list.toTypedArray<EdwardCurvePoint?>()
    }

    internal fun generateRandomScalarAndPoint(prng: PRNGService): ScalarAndPoint {
        var a: BigInteger
        do {
            a = prng.bigInt(q!!)
        } while (a == BigInteger.ONE || a == BigInteger.ZERO)
        val aG = scalarMultiplicationWithX(a, G!!)
        return ScalarAndPoint(a, aG)
    }

    fun isLowOrderPoint(Ay: BigInteger): Boolean {
        return scalarMultiplication(nu!!, Ay) == BigInteger.ONE
    }

    internal class ScalarAndPoint(@JvmField val scalar: BigInteger?, @JvmField val point: EdwardCurvePoint?)
    companion object {
        const val MDC: String = "MDC"
        const val CURVE_25519: String = "Curve_25519"
    }
}


internal class MDC private constructor() : EdwardCurve() {
    init {
        p = BigInteger(
            1,
            byteArrayOf(
                0xf1.toByte(),
                0x3b.toByte(),
                0x68.toByte(),
                0xb9.toByte(),
                0xd4.toByte(),
                0x56.toByte(),
                0xaf.toByte(),
                0xb4.toByte(),
                0x53.toByte(),
                0x2f.toByte(),
                0x92.toByte(),
                0xfd.toByte(),
                0xd7.toByte(),
                0xa5.toByte(),
                0xfd.toByte(),
                0x4f.toByte(),
                0x08.toByte(),
                0x6a.toByte(),
                0x90.toByte(),
                0x37.toByte(),
                0xef.toByte(),
                0x07.toByte(),
                0xaf.toByte(),
                0x9e.toByte(),
                0xc1.toByte(),
                0x37.toByte(),
                0x10.toByte(),
                0x40.toByte(),
                0x57.toByte(),
                0x79.toByte(),
                0xec.toByte(),
                0x13.toByte()
            )
        )
        G = noCheckFactory(
            BigInteger(
                1,
                byteArrayOf(
                    0xb6.toByte(),
                    0x81.toByte(),
                    0x88.toByte(),
                    0x6a.toByte(),
                    0x7f.toByte(),
                    0x90.toByte(),
                    0x3b.toByte(),
                    0x83.toByte(),
                    0xd8.toByte(),
                    0x5b.toByte(),
                    0x42.toByte(),
                    0x1e.toByte(),
                    0x03.toByte(),
                    0xcb.toByte(),
                    0xcf.toByte(),
                    0x63.toByte(),
                    0x50.toByte(),
                    0xd7.toByte(),
                    0x2a.toByte(),
                    0xbb.toByte(),
                    0x8d.toByte(),
                    0x27.toByte(),
                    0x13.toByte(),
                    0xe2.toByte(),
                    0x23.toByte(),
                    0x2c.toByte(),
                    0x25.toByte(),
                    0xbf.toByte(),
                    0xee.toByte(),
                    0x68.toByte(),
                    0x36.toByte(),
                    0x3b.toByte()
                )
            ),
            BigInteger(
                1,
                byteArrayOf(
                    0xca.toByte(),
                    0x67.toByte(),
                    0x34.toByte(),
                    0xe1.toByte(),
                    0xb5.toByte(),
                    0x9c.toByte(),
                    0x0b.toByte(),
                    0x03.toByte(),
                    0x59.toByte(),
                    0x81.toByte(),
                    0x4d.toByte(),
                    0xcf.toByte(),
                    0x65.toByte(),
                    0x63.toByte(),
                    0xda.toByte(),
                    0x42.toByte(),
                    0x1d.toByte(),
                    0xa8.toByte(),
                    0xbc.toByte(),
                    0x3d.toByte(),
                    0x81.toByte(),
                    0xa9.toByte(),
                    0x3a.toByte(),
                    0x3a.toByte(),
                    0x7e.toByte(),
                    0x73.toByte(),
                    0xc3.toByte(),
                    0x55.toByte(),
                    0xbd.toByte(),
                    0x28.toByte(),
                    0x64.toByte(),
                    0xb5.toByte()
                )
            ),
            this
        )
        q = BigInteger(
            1,
            byteArrayOf(
                0x3c.toByte(),
                0x4e.toByte(),
                0xda.toByte(),
                0x2e.toByte(),
                0x75.toByte(),
                0x15.toByte(),
                0xab.toByte(),
                0xed.toByte(),
                0x14.toByte(),
                0xcb.toByte(),
                0xe4.toByte(),
                0xbf.toByte(),
                0x75.toByte(),
                0xe9.toByte(),
                0x7f.toByte(),
                0x53.toByte(),
                0x4f.toByte(),
                0xb3.toByte(),
                0x89.toByte(),
                0x75.toByte(),
                0xfa.toByte(),
                0xf9.toByte(),
                0x74.toByte(),
                0xbb.toByte(),
                0x58.toByte(),
                0x85.toByte(),
                0x52.toByte(),
                0xf4.toByte(),
                0x21.toByte(),
                0xb0.toByte(),
                0xf7.toByte(),
                0xfb.toByte()
            )
        )
        d = BigInteger(
            1,
            byteArrayOf(
                0x57.toByte(),
                0x13.toByte(),
                0x04.toByte(),
                0x52.toByte(),
                0x19.toByte(),
                0x65.toByte(),
                0xb6.toByte(),
                0x8a.toByte(),
                0x7c.toByte(),
                0xdf.toByte(),
                0xbf.toByte(),
                0xcc.toByte(),
                0xfb.toByte(),
                0x0c.toByte(),
                0xb9.toByte(),
                0x62.toByte(),
                0x5f.toByte(),
                0x12.toByte(),
                0x70.toByte(),
                0xf6.toByte(),
                0x3f.toByte(),
                0x21.toByte(),
                0xf0.toByte(),
                0x41.toByte(),
                0xee.toByte(),
                0x93.toByte(),
                0x09.toByte(),
                0x25.toByte(),
                0x03.toByte(),
                0x00.toByte(),
                0xcf.toByte(),
                0x89.toByte()
            )
        )
        nu = BigInteger.valueOf(4)
        nuInv = nu!!.modInverse(q)
        cardinality = q!!.multiply(nu)
        tonelliNonQR = BigInteger.valueOf(2)
        tonelliT = p!!.shiftRight(1)
        tonelliS = 1
        byteLength = 32
    }

    companion object {
        val instance: MDC = MDC()
    }
}

internal class Curve25519 private constructor() : EdwardCurve() {
    init {
        p = BigInteger(
            1,
            byteArrayOf(
                0x7f.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xff.toByte(),
                0xed.toByte()
            )
        )
        G = noCheckFactory(
            BigInteger(
                1,
                byteArrayOf(
                    0x15.toByte(),
                    0x9a.toByte(),
                    0x68.toByte(),
                    0x49.toByte(),
                    0xe4.toByte(),
                    0x4c.toByte(),
                    0x3c.toByte(),
                    0x7f.toByte(),
                    0x06.toByte(),
                    0x1b.toByte(),
                    0x3d.toByte(),
                    0x57.toByte(),
                    0x0f.toByte(),
                    0xc4.toByte(),
                    0xed.toByte(),
                    0x5b.toByte(),
                    0x5d.toByte(),
                    0x14.toByte(),
                    0xc8.toByte(),
                    0xba.toByte(),
                    0x42.toByte(),
                    0x53.toByte(),
                    0xdf.toByte(),
                    0x49.toByte(),
                    0xcc.toByte(),
                    0x7e.toByte(),
                    0xdf.toByte(),
                    0x80.toByte(),
                    0xf5.toByte(),
                    0x33.toByte(),
                    0xad.toByte(),
                    0x9b.toByte()
                )
            ),
            BigInteger(
                1,
                byteArrayOf(
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x66.toByte(),
                    0x58.toByte()
                )
            ),
            this
        )
        q = BigInteger(
            1,
            byteArrayOf(
                0x10.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                0x14.toByte(),
                0xde.toByte(),
                0xf9.toByte(),
                0xde.toByte(),
                0xa2.toByte(),
                0xf7.toByte(),
                0x9c.toByte(),
                0xd6.toByte(),
                0x58.toByte(),
                0x12.toByte(),
                0x63.toByte(),
                0x1a.toByte(),
                0x5c.toByte(),
                0xf5.toByte(),
                0xd3.toByte(),
                0xed.toByte()
            )
        )
        d = BigInteger(
            1,
            byteArrayOf(
                0x2d.toByte(),
                0xfc.toByte(),
                0x93.toByte(),
                0x11.toByte(),
                0xd4.toByte(),
                0x90.toByte(),
                0x01.toByte(),
                0x8c.toByte(),
                0x73.toByte(),
                0x38.toByte(),
                0xbf.toByte(),
                0x86.toByte(),
                0x88.toByte(),
                0x86.toByte(),
                0x17.toByte(),
                0x67.toByte(),
                0xff.toByte(),
                0x8f.toByte(),
                0xf5.toByte(),
                0xb2.toByte(),
                0xbe.toByte(),
                0xbe.toByte(),
                0x27.toByte(),
                0x54.toByte(),
                0x8a.toByte(),
                0x14.toByte(),
                0xb2.toByte(),
                0x35.toByte(),
                0xec.toByte(),
                0xa6.toByte(),
                0x87.toByte(),
                0x4a.toByte()
            )
        )
        nu = BigInteger.valueOf(8)
        nuInv = nu!!.modInverse(q)
        cardinality = q!!.multiply(nu)
        tonelliNonQR = BigInteger.valueOf(2)
        tonelliT = p!!.shiftRight(2)
        tonelliS = 2
        byteLength = 32
    }

    companion object {
        val instance: Curve25519 = Curve25519()
    }
}

