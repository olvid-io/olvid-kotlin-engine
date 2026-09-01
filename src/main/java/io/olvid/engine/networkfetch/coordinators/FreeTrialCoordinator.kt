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
package io.olvid.engine.networkfetch.coordinators

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.operations.FreeTrialOperation
import javax.net.ssl.SSLSocketFactory


class FreeTrialCoordinator(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?
) {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    private val sslSocketFactory: SSLSocketFactory?
    private val userAgentOverride: String?
    private val freeTrialOperationQueue: OperationQueue

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.sslSocketFactory = sslSocketFactory
        this.userAgentOverride = userAgentOverride

        freeTrialOperationQueue = OperationQueue(true)
    }

    fun startProcessing() {
        freeTrialOperationQueue.execute(1, "Engine-FreeTrialCoordinator")
    }

    private fun queueNewFreeTrialOperation(ownedIdentity: Identity, retrieveApiKey: Boolean) {
        val op = FreeTrialOperation(
            fetchManagerSessionFactory,
            sslSocketFactory,
            userAgentOverride,
            ownedIdentity,
            retrieveApiKey
        )
        freeTrialOperationQueue.queue(op)
    }

    fun queryFreeTrial(ownedIdentity: Identity) {
        queueNewFreeTrialOperation(ownedIdentity, false)
    }

    fun startFreeTrial(ownedIdentity: Identity) {
        queueNewFreeTrialOperation(ownedIdentity, true)
    }
}
