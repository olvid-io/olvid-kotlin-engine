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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class LoggerTest {

    @Test
    fun testConstructor() {
        val loggerInstance = Logger()
        assertTrue(loggerInstance is Logger)
    }

    @Test
    fun testJavaStaticDelegation() {
        val loggerClass = Logger::class.java

        // 1. setOutputLogLevel(int)
        loggerClass.getMethod("setOutputLogLevel", Int::class.javaPrimitiveType).invoke(null, Logger.NONE)

        // 2. setOutputter(LogOutputter)
        loggerClass.getMethod("setOutputter", Logger.LogOutputter::class.java).invoke(null, null)

        // 3. d(String)
        loggerClass.getMethod("d", String::class.java).invoke(null, "dummy debug")

        // 4. i(String)
        loggerClass.getMethod("i", String::class.java).invoke(null, "dummy info")

        // 5. w(String)
        loggerClass.getMethod("w", String::class.java).invoke(null, "dummy warn")

        // 6. e(String)
        loggerClass.getMethod("e", String::class.java).invoke(null, "dummy error")

        // 7. e(String, Exception)
        loggerClass.getMethod("e", String::class.java, Exception::class.java).invoke(null, "dummy error ex", Exception("Dummy"))

        // 8. x(Throwable)
        loggerClass.getMethod("x", Throwable::class.java).invoke(null, Exception("Dummy x"))

        // 9. toHexString(byte[])
        val hex = loggerClass.getMethod("toHexString", ByteArray::class.java).invoke(null, byteArrayOf(0x00)) as String
        assertEquals("00", hex)

        // 10. fromHexString(String)
        val bytes = loggerClass.getMethod("fromHexString", String::class.java).invoke(null, "00") as ByteArray
        assertArrayEquals(byteArrayOf(0x00), bytes)

        // 11. getUuidString(UUID)
        val uuid = UUID.randomUUID()
        val uuidStr = loggerClass.getMethod("getUuidString", UUID::class.java).invoke(null, uuid) as String
        assertEquals(uuid.toString(), uuidStr)
    }

    @Test
    fun testGetUuidString() {
        for (i in 0 until 5000) {
            val uuid = UUID.randomUUID()
            assertEquals(uuid.toString(), Logger.getUuidString(uuid))
        }
        // Test null case
        assertEquals("", Logger.getUuidString(null))
    }

    @Test
    fun testHexConversion() {
        val original = byteArrayOf(0x00, 0x01, 0x0A, 0x0F, 0x80.toByte(), 0xFF.toByte())
        val expectedHex = "00010A0F80FF"

        // Test toHexString
        val hex = Logger.toHexString(original)
        assertEquals(expectedHex, hex)

        // Test fromHexString
        val decoded = Logger.fromHexString(hex)
        assertEquals(original.size, decoded.size)
        for (i in original.indices) {
            assertEquals(original[i], decoded[i])
        }

        // Test round trip for empty array
        val empty = byteArrayOf()
        assertEquals("", Logger.toHexString(empty))
        assertEquals(0, Logger.fromHexString("").size)

        // Test invalid hex conversion (odd length)
        try {
            Logger.fromHexString("1")
        } catch (_: Exception) {
            // expected
        }

        // Test invalid hex characters
        val invalidHex = "G0"
        val invalidDecoded = Logger.fromHexString(invalidHex)
        assertEquals(1, invalidDecoded.size)
    }

    private class CapturedLog(
        val type: String,
        val tag: String,
        val message: String?,
        val throwable: Throwable?
    )

    private class TestLogOutputter : Logger.LogOutputter {
        val logs = mutableListOf<CapturedLog>()

        override fun d(tag: String, message: String) {
            logs.add(CapturedLog("DEBUG", tag, message, null))
        }

        override fun i(tag: String, message: String) {
            logs.add(CapturedLog("INFO", tag, message, null))
        }

        override fun w(tag: String, message: String) {
            logs.add(CapturedLog("WARN", tag, message, null))
        }

        override fun e(tag: String, message: String) {
            logs.add(CapturedLog("ERROR", tag, message, null))
        }

        override fun x(tag: String, throwable: Throwable) {
            logs.add(CapturedLog("THROWABLE", tag, null, throwable))
        }
    }

    @Test
    fun testLoggingLevelsAndOutputter() {
        val testOutputter = TestLogOutputter()
        Logger.setOutputter(testOutputter)

        // Test Level filtering - set to NONE
        Logger.setOutputLogLevel(Logger.NONE)
        Logger.d("This should not be logged")
        Logger.i("This should not be logged")
        Logger.w("This should not be logged")
        Logger.e("This should not be logged")
        assertEquals(0, testOutputter.logs.size)

        // Test Level filtering - set to DEBUG (logs everything)
        Logger.setOutputLogLevel(Logger.DEBUG)
        Logger.d("Debug message")
        Logger.i("Info message")
        Logger.w("Warn message")
        Logger.e("Error message")

        assertEquals(4, testOutputter.logs.size)
        assertEquals("DEBUG", testOutputter.logs[0].type)
        assertEquals("Debug message", testOutputter.logs[0].message)
        assertEquals("INFO", testOutputter.logs[1].type)
        assertEquals("Info message", testOutputter.logs[1].message)
        assertEquals("WARN", testOutputter.logs[2].type)
        assertEquals("Warn message", testOutputter.logs[2].message)
        assertEquals("ERROR", testOutputter.logs[3].type)
        assertEquals("Error message", testOutputter.logs[3].message)

        testOutputter.logs.clear()

        // Test Level filtering - set to WARNING
        Logger.setOutputLogLevel(Logger.WARNING)
        Logger.d("Debug message")
        Logger.i("Info message")
        Logger.w("Warn message")
        Logger.e("Error message")

        assertEquals(2, testOutputter.logs.size)
        assertEquals("WARN", testOutputter.logs[0].type)
        assertEquals("ERROR", testOutputter.logs[1].type)

        testOutputter.logs.clear()

        // Test exception log helpers
        Logger.setOutputLogLevel(Logger.DEBUG)
        val testEx = Exception("Test exception")
        Logger.e("Error with exception: ", testEx)

        // Expect two captured logs: one ERROR log with description, and one THROWABLE log
        assertEquals(2, testOutputter.logs.size)
        assertEquals("ERROR", testOutputter.logs[0].type)
        assertTrue(testOutputter.logs[0].message?.contains("Error with exception: ") == true)
        assertTrue(testOutputter.logs[0].message?.contains("Test exception") == true)

        assertEquals("THROWABLE", testOutputter.logs[1].type)
        assertEquals(testEx, testOutputter.logs[1].throwable)

        // Reset Logger to default clean state
        Logger.setOutputter(null)
        Logger.setOutputLogLevel(Logger.NONE)

        // Test logging to System.out when outputter is null
        Logger.setOutputLogLevel(Logger.DEBUG)
        Logger.d("System.out debug log")
        Logger.i("System.out info log")
        Logger.w("System.out warn log")
        Logger.e("System.out error log")
        Logger.e("System.out error log with exception", Exception("Dummy"))

        // Test exception log helper directly when level is low
        Logger.setOutputLogLevel(Logger.NONE)
        Logger.x(Exception("Dummy exception"))

        // Test exception log helper when outputter is null but level is warning
        Logger.setOutputLogLevel(Logger.WARNING)
        Logger.x(Exception("Dummy exception with null outputter"))
        
        // Reset Logger to default clean state
        Logger.setOutputLogLevel(Logger.NONE)
    }

    @Test
    fun testLogPrivateMethodReflection() {
        val companionClass = Logger.Companion::class.java
        val logMethod = companionClass.getDeclaredMethod("log", Int::class.javaPrimitiveType, String::class.java)
        logMethod.isAccessible = true

        val testOutputter = TestLogOutputter()
        Logger.setOutputter(testOutputter)
        Logger.setOutputLogLevel(Logger.DEBUG)

        // Call private log method with a level not handled in when (e.g. 999)
        logMethod.invoke(Logger.Companion, 999, "unhandled level log")

        // Verifies that it fell through without calling any outputter method
        assertEquals(0, testOutputter.logs.size)

        // Clean up
        Logger.setOutputter(null)
        Logger.setOutputLogLevel(Logger.NONE)
    }
}
