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
package io.olvid.engine.networkfetch.datatypes

import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

// Masks of the Android push configurations. They are loaded from the database a few hundred ms after the engine
// starts, while a push that starts the app is processed right away: lookups wait (bounded) for that first load.
class AndroidIdentityMaskingUidRegistry(private val loadTimeoutMillis: Long = DEFAULT_LOAD_TIMEOUT_MILLIS) {
    private val identityAndUids = ConcurrentHashMap<UID, IdentityAndUid>()
    private val loaded = CountDownLatch(1)

    fun put(identityMaskingUid: UID, identityAndUid: IdentityAndUid) {
        identityAndUids[identityMaskingUid] = identityAndUid
    }

    fun markLoaded() {
        loaded.countDown()
    }

    fun get(identityMaskingUid: UID): IdentityAndUid? {
        identityAndUids[identityMaskingUid]?.let { return it }
        if (loaded.count > 0) {
            try {
                loaded.await(loadTimeoutMillis, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        return identityAndUids[identityMaskingUid]
    }

    companion object {
        const val DEFAULT_LOAD_TIMEOUT_MILLIS = 10_000L
    }
}
