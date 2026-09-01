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

import java.util.Arrays
import java.util.regex.Pattern

class ObvBase64 {
    companion object {
        private val base64Map = CharArray(64)
        private val invBase64Map = IntArray(128)

        init {
            Arrays.fill(invBase64Map, -1)
            var i = 0
            for (c in 'A'..'Z') {
                invBase64Map[c.code] = i
                base64Map[i++] = c
            }
            for (c in 'a'..'z') {
                invBase64Map[c.code] = i
                base64Map[i++] = c
            }
            for (c in '0'..'9') {
                invBase64Map[c.code] = i
                base64Map[i++] = c
            }
            invBase64Map['-'.code] = i
            base64Map[i++] = '-'
            invBase64Map['_'.code] = i
            base64Map[i] = '_'
        }

        private val pattern = Pattern.compile("^[-_a-zA-Z0-9]*$")

        @JvmStatic
        fun encode(bytes: ByteArray): String {
            val base64len = 1 + (bytes.size * 4 - 1) / 3
            val chars = CharArray(base64len)
            var srcPos = 0
            var outPos = 0
            while (srcPos < bytes.size - 2) {
                val buffer = ((bytes[srcPos].toInt() and 0xff) shl 16) xor
                        ((bytes[srcPos + 1].toInt() and 0xff) shl 8) xor
                        (bytes[srcPos + 2].toInt() and 0xff)
                srcPos += 3
                chars[outPos++] = base64Map[buffer shr 18]
                chars[outPos++] = base64Map[(buffer shr 12) and 63]
                chars[outPos++] = base64Map[(buffer shr 6) and 63]
                chars[outPos++] = base64Map[buffer and 63]
            }
            if (srcPos == bytes.size - 1) {
                val buffer = bytes[srcPos].toInt() and 0xff
                chars[outPos++] = base64Map[(buffer shr 2) and 63]
                chars[outPos++] = base64Map[(buffer shl 4) and 63]
            }
            if (srcPos == bytes.size - 2) {
                val buffer = ((bytes[srcPos].toInt() and 0xff) shl 8) xor
                        (bytes[srcPos + 1].toInt() and 0xff)
                chars[outPos++] = base64Map[(buffer shr 10) and 63]
                chars[outPos++] = base64Map[(buffer shr 4) and 63]
                chars[outPos] = base64Map[(buffer shl 2) and 63]
            }
            return String(chars)
        }

        @JvmStatic
        @Throws(Exception::class)
        fun decode(base64: String): ByteArray {
            val sanitizedBase64 = base64.replace("=+$".toRegex(), "") // this removes potential Base 64 padding
            val chars = sanitizedBase64.toCharArray()
            if ((chars.size and 3) == 1) {
                throw Exception()
            }
            if (!pattern.matcher(sanitizedBase64).matches()) {
                throw Exception()
            }
            val bytelen = chars.size * 3 / 4
            val bytes = ByteArray(bytelen)
            var srcPos = 0
            var outPos = 0
            while (srcPos < chars.size - 3) {
                var buffer: Int
                buffer = invBase64Map[chars[srcPos++].code] shl 18
                buffer = buffer xor (invBase64Map[chars[srcPos++].code] shl 12)
                buffer = buffer xor (invBase64Map[chars[srcPos++].code] shl 6)
                buffer = buffer xor invBase64Map[chars[srcPos++].code]

                bytes[outPos++] = (buffer shr 16).toByte()
                bytes[outPos++] = (buffer shr 8).toByte()
                bytes[outPos++] = buffer.toByte()
            }
            if (srcPos == chars.size - 2) {
                var buffer: Int
                buffer = invBase64Map[chars[srcPos++].code] shl 18
                buffer = buffer xor (invBase64Map[chars[srcPos++].code] shl 12)

                bytes[outPos++] = (buffer shr 16).toByte()
            }
            if (srcPos == chars.size - 3) {
                var buffer: Int
                buffer = invBase64Map[chars[srcPos++].code] shl 18
                buffer = buffer xor (invBase64Map[chars[srcPos++].code] shl 12)
                buffer = buffer xor (invBase64Map[chars[srcPos].code] shl 6)

                bytes[outPos++] = (buffer shr 16).toByte()
                bytes[outPos] = (buffer shr 8).toByte()
            }
            return bytes
        }
    }
}
