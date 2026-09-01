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

import io.olvid.engine.Logger
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

open class NoExceptionSingleThreadExecutor(name: String) : Executor {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, name) }

    override fun execute(r: Runnable) {
        try {
            executor.execute {
                try {
                    r.run()
                } catch (e: Exception) {
                    // do nothing, this is sometimes normal
                    Logger.x(e)
                } catch (e: Error) {
                    Logger.x(e)
                }
            }
        } catch (e: Exception) {
            // do nothing, this is sometimes normal
            Logger.x(e)
        } catch (e: Error) {
            Logger.x(e)
        }
    }

    fun shutdownNow() {
        try {
            executor.shutdownNow()
        } catch (e: Exception) {
            Logger.x(e)
        } catch (e: Error) {
            Logger.x(e)
        }
    }
}
