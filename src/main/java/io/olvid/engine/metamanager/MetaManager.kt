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
import java.lang.reflect.InvocationTargetException
import java.util.Collections
import java.util.PriorityQueue
import java.util.concurrent.locks.ReentrantLock
import java.util.function.ToIntFunction


class MetaManager {
    private val registeredInterfaceImplementations: HashMap<String, Any> = HashMap()
    private val managersAwaitingInterfaceImplementations: HashMap<String, ArrayList<ObvManager>> = HashMap()
    private val registeredManagers: MutableSet<ObvManager> =
        Collections.newSetFromMap(Collections.synchronizedMap(HashMap()))
    private val registeredDelegates: MutableSet<Any> =
        Collections.newSetFromMap(Collections.synchronizedMap(HashMap()))
    private val lockOnInterfaceImplementations: ReentrantLock = ReentrantLock()

    @Throws(Exception::class)
    fun initializationComplete() {
        if (!managersAwaitingInterfaceImplementations.isEmpty()) {
            Logger.e("Called initializationComplete but some managers are still awaiting some delegates.")
            for (entry in managersAwaitingInterfaceImplementations.entries) {
                Logger.e("Missing delegate for " + entry.key)
            }
            throw Exception()
        }
        Logger.i("✔️✔️✔️✔️ Engine initialisation complete. All managers have their requested delegates set.")
        Thread {
            try {
                Thread.sleep(300)
            } catch (_: InterruptedException) {
                // do nothing
            }
            val sortedManagers = PriorityQueue(
                registeredManagers.size, Comparator.comparingInt(
                    ToIntFunction { obj: ObvManager? -> obj!!.initialQueueingPriority() })
            )
            sortedManagers.addAll(registeredManagers)
            for (manager in sortedManagers) {
                try {
                    manager.initialisationComplete()
                } catch (e: Exception) {
                    Logger.e("Exception in initialisationComplete() for " + manager.javaClass)
                    Logger.x(e)
                }
            }
        }.start()
    }

    fun registerImplementedDelegates(delegatesImplementation: Any) {
        registeredDelegates.add(delegatesImplementation)
        checkInterfaceImplementations(delegatesImplementation)
    }

    fun requestDelegate(manager: ObvManager, interfaceClass: Class<*>) {
//        Logger.d("Manager " + manager.getClass() + " requesting delegate " + interfaceClass);
        val interfaceName = interfaceClass.getName()

        registeredManagers.add(manager)

        lockOnInterfaceImplementations.lock()
        val delegate = registeredInterfaceImplementations.get(interfaceName)
        // first check whether this interface is already registered
        if (delegate != null) {
//            Logger.d("A delegate of " + delegate.getClass() + " was already cached for " + interfaceName);
            setManagerDelegate(manager, delegate, interfaceName)
        } else {
            // the interface was never registered
            // check if any of the registered delegates implements it:
            for (registeredDelegate in registeredDelegates) {
                if (interfaceClass.isInstance(registeredDelegate)) {
//                    Logger.d("Found " + registeredDelegate.getClass() + " implementing " + interfaceName);
                    registeredInterfaceImplementations.put(interfaceName, registeredDelegate)
                    setManagerDelegate(manager, registeredDelegate, interfaceName)
                    lockOnInterfaceImplementations.unlock()
                    return
                }
            }
            // no registered delegate implements the interface, add the manager to the list of waiting managers
//            Logger.d("No delegate found implementing " + interfaceName);
            var waitingManagers = managersAwaitingInterfaceImplementations.get(interfaceName)
            if (waitingManagers == null) {
                waitingManagers = ArrayList()
                managersAwaitingInterfaceImplementations.put(interfaceName, waitingManagers)
            }
            waitingManagers.add(manager)
        }
        lockOnInterfaceImplementations.unlock()
    }

    private fun setManagerDelegate(manager: ObvManager, delegate: Any?, interfaceName: String) {
        try {
//            Logger.d("Setting delegate " + delegate.getClass() + " as " + interfaceName + " for manager " + manager.getClass());
            val method = manager.javaClass.getMethod("setDelegate", Class.forName(interfaceName))
            method.invoke(manager, delegate)
        } catch (e: ClassNotFoundException) {
            Logger.x(e)
        } catch (e: IllegalAccessException) {
            Logger.x(e)
        } catch (e: InvocationTargetException) {
            Logger.x(e)
        } catch (e: NoSuchMethodException) {
            Logger.e("ObvManager " + manager.javaClass + " requests a delegate of type " + interfaceName + " but does not implement the matching setDelegate method.")
            throw RuntimeException()
        }
    }

    private fun checkInterfaceImplementations(delegatesImplementation: Any) {
        lockOnInterfaceImplementations.lock()
        // first check that this new delegatesImplementation does not implement any of the registered interface implementations
        for (interfaceName in registeredInterfaceImplementations.keys) {
            try {
                if (Class.forName(interfaceName).isInstance(delegatesImplementation)) {
                    Logger.e(
                        "The MetaManager received two managers implementing $interfaceName:\n  " + registeredInterfaceImplementations[interfaceName] + "\n  " + delegatesImplementation.javaClass
                    )
                    throw RuntimeException()
                }
            } catch (e: ClassNotFoundException) {
                Logger.x(e)
            }
        }

        // then, check all managers awaiting an interface implementation
        for (interfaceName in managersAwaitingInterfaceImplementations.keys.toTypedArray<String>()) {
            try {
                if (Class.forName(interfaceName).isInstance(delegatesImplementation)) {
                    registeredInterfaceImplementations.put(interfaceName, delegatesImplementation)
                    for (waitingManager in managersAwaitingInterfaceImplementations.get(
                        interfaceName
                    )!!) {
                        setManagerDelegate(waitingManager, delegatesImplementation, interfaceName)
                    }
                    managersAwaitingInterfaceImplementations.remove(interfaceName)
                }
            } catch (e: ClassNotFoundException) {
                Logger.x(e)
            }
        }
        lockOnInterfaceImplementations.unlock()
    }
}
