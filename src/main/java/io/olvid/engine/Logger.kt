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

package io.olvid.engine

import java.util.UUID

class Logger {

    interface LogOutputter {
        fun d(tag: String, message: String)
        fun i(tag: String, message: String)
        fun w(tag: String, message: String)
        fun e(tag: String, message: String)
        fun x(tag: String, throwable: Throwable)
    }

    companion object {
        const val DEBUG = 0
        const val INFO = 1
        const val WARNING = 2
        const val ERROR = 3
        const val NONE = 10

        private var outputLogLevel = NONE
        private var outputter: LogOutputter? = null

        @JvmStatic
        fun setOutputter(newOutputter: LogOutputter?) {
            outputter = newOutputter
        }

        private fun log(logLevel: Int, message: String) {
            if (logLevel >= outputLogLevel) {
                val currentOutputter = outputter
                if (currentOutputter == null) {
                    println(message)
                } else {
                    when (logLevel) {
                        DEBUG -> currentOutputter.d("Logger", message)
                        INFO -> currentOutputter.i("Logger", message)
                        WARNING -> currentOutputter.w("Logger", message)
                        ERROR -> currentOutputter.e("Logger", message)
                    }
                }
            }
        }

        @JvmStatic
        fun setOutputLogLevel(newOutputLogLevel: Int) {
            outputLogLevel = newOutputLogLevel
        }

        @JvmStatic
        fun d(message: String) {
            log(DEBUG, message)
        }

        @JvmStatic
        fun i(message: String) {
            log(INFO, message)
        }

        @JvmStatic
        fun w(message: String) {
            log(WARNING, message)
        }

        @JvmStatic
        fun e(message: String) {
            log(ERROR, message)
        }

        @JvmStatic
        fun e(message: String, e: Exception) {
            log(ERROR, "$message( $e)")
            x(e)
        }

        @JvmStatic
        fun x(throwable: Throwable) {
            if (WARNING >= outputLogLevel) {
                outputter?.x("Logger", throwable)
            }
        }

        private val hexArray = "0123456789ABCDEF".toCharArray()

        @JvmStatic
        fun toHexString(bytes: ByteArray): String {
            val hexChars = CharArray(bytes.size * 2)
            for (j in bytes.indices) {
                val v = bytes[j].toInt() and 0xFF
                hexChars[j * 2] = hexArray[v ushr 4]
                hexChars[j * 2 + 1] = hexArray[v and 0x0F]
            }
            return String(hexChars)
        }

        @JvmStatic
        fun fromHexString(hex: String): ByteArray {
            val len = hex.length
            val data = ByteArray(len / 2)
            var i = 0
            while (i < len) {
                data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
                i += 2
            }
            return data
        }

        @JvmStatic
        fun getUuidString(uuid: UUID?): String {
            if (uuid == null) {
                return ""
            }
            return (digits(uuid.mostSignificantBits shr 32, 8) + "-" +
                    digits(uuid.mostSignificantBits shr 16, 4) + "-" +
                    digits(uuid.mostSignificantBits, 4) + "-" +
                    digits(uuid.leastSignificantBits shr 48, 4) + "-" +
                    digits(uuid.leastSignificantBits, 12))
        }

        private fun digits(value: Long, digits: Int): String {
            val hi = 1L shl (digits * 4)
            return java.lang.Long.toHexString(hi or (value and (hi - 1))).substring(1)
        }
    }
}
