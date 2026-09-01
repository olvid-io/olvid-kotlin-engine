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

package io.olvid.engine.notification

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NotificationListeningDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import java.lang.ref.WeakReference
import java.util.HashMap
import java.util.concurrent.locks.ReentrantLock

class NotificationManager(metaManager: MetaManager) :
    NotificationListeningDelegate, NotificationPostingDelegate, ObvManager {

    private var instanceCounter: Long = 0
    private val listeners: HashMap<String, HashMap<Long, WeakReference<NotificationListener>>> = HashMap()
    private val listenersLock: ReentrantLock = ReentrantLock()

    init {
        metaManager.registerImplementedDelegates(this)
    }

    override fun initialQueueingPriority(): Int = 1000

    override fun initialisationComplete() {
        // Nothing to do here
    }

    @Synchronized
    private fun getInstanceNumber(): Long {
        val instanceNumber = instanceCounter
        instanceCounter++
        return instanceNumber
    }

    // region implement NotificationListeningDelegate

    override fun addListener(notificationName: String, notificationListener: NotificationListener): Long {
        listenersLock.lock()
        val listenerNumber = getInstanceNumber()
        var notificationObservers = listeners[notificationName]
        if (notificationObservers == null) {
            notificationObservers = HashMap()
            listeners[notificationName] = notificationObservers
        }
        val weakReference = WeakReference(notificationListener)
        notificationObservers[listenerNumber] = weakReference
        listenersLock.unlock()
        return listenerNumber
    }

    override fun removeListener(notificationName: String, notificationListenerNumber: Long) {
        listenersLock.lock()
        val notificationObservers = listeners[notificationName]
        notificationObservers?.remove(notificationListenerNumber)
        listenersLock.unlock()
    }

    // endregion

    // region implement NotificationPostingDelegate

    override fun postNotification(notificationName: String, userInfo: Map<String, Any>) {
        Logger.d("Posting notification with name $notificationName")
        listenersLock.lock()
        val notificationObservers = listeners[notificationName]
        if (notificationObservers != null) {
            // clone the HashMap so we can iterate outside the lock
            val snapshot = HashMap(notificationObservers)
            listenersLock.unlock()
            for ((listenerNumber, weakReference) in snapshot) {
                val listener = weakReference.get()
                if (listener == null) {
                    removeListener(notificationName, listenerNumber)
                } else {
                    try {
                        listener.callback(notificationName, userInfo)
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
            }
        } else {
            listenersLock.unlock()
        }
    }

    // endregion
}
