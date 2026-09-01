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

import org.junit.Assert.*
import org.junit.Test
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit

class NoExceptionSingleThreadExecutorTest {

    @Test
    fun testConstructorAndNormalExecution() {
        val threadNamePrefix = "test-thread-executor"
        val executor = NoExceptionSingleThreadExecutor(threadNamePrefix)
        val latch = CountDownLatch(1)
        var actualThreadName: String? = null

        executor.execute {
            actualThreadName = Thread.currentThread().name
            latch.countDown()
        }

        assertTrue(latch.await(2, TimeUnit.SECONDS))
        assertEquals(threadNamePrefix, actualThreadName)
        executor.shutdownNow()
    }

    @Test
    fun testExecuteAfterShutdown() {
        val executor = NoExceptionSingleThreadExecutor("test-shutdown")
        executor.shutdownNow()

        // Should not throw or crash even if execution is rejected after shutdown
        var ran = false
        executor.execute {
            ran = true
        }
        assertFalse(ran)
    }

    @Test
    fun testExecuteWithReflectionExceptionsAndErrors() {
        val executor = NoExceptionSingleThreadExecutor("test-reflection")
        val executorField = NoExceptionSingleThreadExecutor::class.java.getDeclaredField("executor")
        executorField.isAccessible = true

        // Throw an Exception during execute
        val exceptionProxy = Proxy.newProxyInstance(
            ExecutorService::class.java.classLoader,
            arrayOf(ExecutorService::class.java)
        ) { _, method, _ ->
            if (method.name == "execute") {
                throw RuntimeException("Mocked Exception")
            }
            null
        } as ExecutorService

        executorField.set(executor, exceptionProxy)
        // This should not throw, as Exception is caught
        executor.execute { }

        // Throw an Error during execute
        val errorProxy = Proxy.newProxyInstance(
            ExecutorService::class.java.classLoader,
            arrayOf(ExecutorService::class.java)
        ) { _, method, _ ->
            if (method.name == "execute") {
                throw OutOfMemoryError("Mocked Error")
            }
            null
        } as ExecutorService

        executorField.set(executor, errorProxy)
        // This should not throw, as Error is caught
        executor.execute { }
    }

    @Test
    fun testShutdownWithReflectionExceptionsAndErrors() {
        val executor = NoExceptionSingleThreadExecutor("test-shutdown-reflection")
        val executorField = NoExceptionSingleThreadExecutor::class.java.getDeclaredField("executor")
        executorField.isAccessible = true

        // Throw an Exception during shutdownNow
        val exceptionProxy = Proxy.newProxyInstance(
            ExecutorService::class.java.classLoader,
            arrayOf(ExecutorService::class.java)
        ) { _, method, _ ->
            if (method.name == "shutdownNow") {
                throw RuntimeException("Mocked Shutdown Exception")
            }
            null
        } as ExecutorService

        executorField.set(executor, exceptionProxy)
        // This should not throw and should log the error
        executor.shutdownNow()

        // Throw an Error during shutdownNow
        val errorProxy = Proxy.newProxyInstance(
            ExecutorService::class.java.classLoader,
            arrayOf(ExecutorService::class.java)
        ) { _, method, _ ->
            if (method.name == "shutdownNow") {
                throw OutOfMemoryError("Mocked Shutdown Error")
            }
            null
        } as ExecutorService

        executorField.set(executor, errorProxy)
        // This should not throw and should log the error
        executor.shutdownNow()
    }
}
