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

package io.olvid.engine.metamanager

import io.olvid.engine.Logger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Characterization tests for [MetaManager] — the engine's reflection-based
 * dependency-injection container.
 *
 * Written before migrating the metamanager/ package from Java to Kotlin so we
 * have a behavioral safety net (the package had 5% coverage at baseline).
 */
class MetaManagerTest {

    @Before
    fun silenceLogger() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
    }

    // --- test-only delegate interfaces ---
    interface FooDelegate {
        fun foo(): String
    }

    interface BarDelegate {
        fun bar(): String
    }

    // --- test-only delegate implementations ---
    class FooImpl : FooDelegate {
        override fun foo() = "foo"
    }

    class BarImpl : BarDelegate {
        override fun bar() = "bar"
    }

    /** One object implementing two delegate interfaces — exercises the multi-interface registration path. */
    class FooAndBarImpl : FooDelegate, BarDelegate {
        override fun foo() = "combo-foo"
        override fun bar() = "combo-bar"
    }

    // --- test-only managers ---
    // MetaManager wires delegates via reflection: it looks for a `setDelegate(InterfaceType)` method.
    // The setter signature must take the interface (not the impl) — JVM reflection requires exact match.

    // The Kotlin `var delegate: X?` auto-generates a public `setDelegate(X)` method
    // matching what MetaManager looks for via reflection. No explicit setter needed.
    class FooManager(private val priority: Int = 0) : ObvManager {
        var delegate: FooDelegate? = null
        var initCalledAt: Long = 0L

        override fun initialQueueingPriority(): Int = priority
        override fun initialisationComplete() {
            initCalledAt = System.nanoTime()
        }
    }

    class BarManager : ObvManager {
        var delegate: BarDelegate? = null
        var initCalledAt: Long = 0L

        override fun initialQueueingPriority(): Int = 0
        override fun initialisationComplete() {
            initCalledAt = System.nanoTime()
        }
    }

    /** Manager that asks for a delegate but doesn't implement `setDelegate(InterfaceType)`. */
    class BrokenManager : ObvManager {
        override fun initialQueueingPriority(): Int = 0
        override fun initialisationComplete() {}
    }

    // --- behaviors under test ---

    @Test
    fun `register-then-request wires the delegate via reflection`() {
        val mm = MetaManager()
        val impl = FooImpl()
        mm.registerImplementedDelegates(impl)
        val manager = FooManager()
        mm.requestDelegate(manager, FooDelegate::class.java)
        assertSame(impl, manager.delegate)
    }

    @Test
    fun `request-then-register queues the manager and wires it on register`() {
        val mm = MetaManager()
        val manager = FooManager()
        mm.requestDelegate(manager, FooDelegate::class.java)
        assertNull("manager should be queued, not yet wired", manager.delegate)
        val impl = FooImpl()
        mm.registerImplementedDelegates(impl)
        assertSame(impl, manager.delegate)
    }

    @Test
    fun `one impl can satisfy multiple delegate interfaces`() {
        val mm = MetaManager()
        val impl = FooAndBarImpl()
        mm.registerImplementedDelegates(impl)

        val fooMgr = FooManager()
        val barMgr = BarManager()
        mm.requestDelegate(fooMgr, FooDelegate::class.java)
        mm.requestDelegate(barMgr, BarDelegate::class.java)

        assertSame(impl, fooMgr.delegate)
        assertSame(impl, barMgr.delegate)
    }

    @Test
    fun `multiple managers can wait for the same delegate before registration`() {
        val mm = MetaManager()
        val mgrA = FooManager()
        val mgrB = FooManager()
        mm.requestDelegate(mgrA, FooDelegate::class.java)
        mm.requestDelegate(mgrB, FooDelegate::class.java)

        val impl = FooImpl()
        mm.registerImplementedDelegates(impl)
        assertSame(impl, mgrA.delegate)
        assertSame(impl, mgrB.delegate)
    }

    @Test
    fun `registering a second impl of an interface that is already cached throws`() {
        val mm = MetaManager()
        mm.registerImplementedDelegates(FooImpl())
        // First request caches the impl in registeredInterfaceImplementations.
        mm.requestDelegate(FooManager(), FooDelegate::class.java)
        // Registering ANOTHER impl of FooDelegate triggers the duplicate check.
        assertThrows(RuntimeException::class.java) {
            mm.registerImplementedDelegates(FooImpl())
        }
    }

    @Test
    fun `manager without setDelegate method throws when delegate is found`() {
        val mm = MetaManager()
        mm.registerImplementedDelegates(FooImpl())
        assertThrows(RuntimeException::class.java) {
            mm.requestDelegate(BrokenManager(), FooDelegate::class.java)
        }
    }

    @Test
    fun `initializationComplete throws when managers are still awaiting delegates`() {
        val mm = MetaManager()
        mm.requestDelegate(FooManager(), FooDelegate::class.java)
        // FooDelegate never registered → manager still waiting.
        assertThrows(Exception::class.java) {
            mm.initializationComplete()
        }
    }

    @Test
    fun `initializationComplete succeeds with no managers registered`() {
        val mm = MetaManager()
        // No managers, no delegates. Should not throw.
        mm.initializationComplete()
    }

    @Test
    fun `initializationComplete calls initialisationComplete on managers in priority order`() {
        val mm = MetaManager()
        mm.registerImplementedDelegates(FooImpl())

        // Lower priority value runs first (Comparator.comparingInt is ascending).
        val low = FooManager(priority = -10)
        val high = FooManager(priority = 100)
        // Register them in the opposite order to verify it's the priority — not insertion order — that wins.
        mm.requestDelegate(high, FooDelegate::class.java)
        mm.requestDelegate(low, FooDelegate::class.java)

        mm.initializationComplete()

        // initialisationComplete is run on a background thread that sleeps 300ms first.
        // Wait up to 2s for both to fire.
        val deadline = System.currentTimeMillis() + 2000
        while (System.currentTimeMillis() < deadline &&
            (low.initCalledAt == 0L || high.initCalledAt == 0L)
        ) {
            Thread.sleep(20)
        }

        assertTrue("low priority manager should have been initialised", low.initCalledAt > 0)
        assertTrue("high priority manager should have been initialised", high.initCalledAt > 0)
        assertTrue(
            "low priority manager should be initialised before high priority",
            low.initCalledAt <= high.initCalledAt
        )
    }

    @Test
    fun `request for an interface no one implements leaves the manager queued indefinitely`() {
        val mm = MetaManager()
        val manager = FooManager()
        mm.requestDelegate(manager, FooDelegate::class.java)
        assertNull(manager.delegate)
        // Register an unrelated impl — should NOT wire the FooManager.
        mm.registerImplementedDelegates(BarImpl())
        assertNull(manager.delegate)
    }

    @Test
    fun `re-registering the same impl instance still throws once it's cached`() {
        // Characterization: the duplicate check uses Class.isInstance, not object
        // identity. Once an impl is in registeredInterfaceImplementations (i.e. some
        // manager has requested it), re-registering the SAME instance triggers the
        // duplicate-implementor RuntimeException.
        val mm = MetaManager()
        val impl = FooImpl()
        mm.registerImplementedDelegates(impl)
        mm.requestDelegate(FooManager(), FooDelegate::class.java)
        assertThrows(RuntimeException::class.java) {
            mm.registerImplementedDelegates(impl)
        }
    }

    @Test
    fun `register without any waiting manager just caches the delegate`() {
        val mm = MetaManager()
        mm.registerImplementedDelegates(FooImpl())
        // No exception. initializationComplete succeeds (no managers waiting).
        mm.initializationComplete()
    }
}
