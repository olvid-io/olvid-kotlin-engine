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
package io.olvid.engine.networkfetch.operations

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.metamanager.SolveChallengeDelegate
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import javax.net.ssl.SSLSocketFactory

class CreateServerSessionCompositeOperation(
    fetchManagerSessionFactory: FetchManagerSessionFactory?,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?, //    public static final int RFC_API_KEY_REJECTED = 8;
    @JvmField val ownedIdentity: Identity,
    solveChallengeDelegate: SolveChallengeDelegate?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    ownedIdentity.computeUniqueUid(), onFinishCallback, onCancelCallback
), OnFinishCallback {
    private val suboperations: Array<Operation>

    var apiKeyStatus: ServerSession.ApiKeyStatus? = null
        private set
    var permissions: MutableList<ServerSession.Permission?>? = null
        private set
    var apiKeyExpirationTimestamp: Long = 0
        private set

    init {
        this.suboperations = arrayOf<Operation>(
            RequestChallengeOperation(
                fetchManagerSessionFactory!!, sslSocketFactory, userAgentOverride,
                ownedIdentity
            ),
            SolveChallengeOperation(
                fetchManagerSessionFactory,
                ownedIdentity, solveChallengeDelegate!!
            ),
            GetTokenOperation(
                fetchManagerSessionFactory, sslSocketFactory, userAgentOverride,
                ownedIdentity, this
            )
        )

        for (i in 0..<suboperations.size - 1) {
            suboperations[i + 1].addDependency(suboperations[i])
        }
    }

    override fun doCancel() {
        for (op in suboperations) {
            op.cancel(null)
        }
    }

    override fun doExecute() {
        var finished = false
        try {
            val queue = OperationQueue()
            for (op in suboperations) {
                queue.queue(op)
            }
            queue.execute(1, "Engine-CreateServerSessionCompositeOperation")
            queue.join()

            if (cancelWasRequested()) {
                return
            }

            for (op in suboperations) {
                if (op.isCancelled) {
                    cancel(op.reasonForCancel)
                    return
                }
            }
            finished = true
        } catch (e: Exception) {
            Logger.x(e)
        } finally {
            if (finished) {
                setFinished()
            } else {
                cancel(null)
                processCancel()
            }
        }
    }

    override fun onFinishCallback(operation: Operation) {
        if (operation is GetTokenOperation) {
            val op = operation
            apiKeyStatus = op.apiKeyStatus
            permissions = op.permissions
            apiKeyExpirationTimestamp = op.apiKeyExpirationTimestamp
        }
    }

    companion object {
        // possible reasons for cancel
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_SESSION_CANNOT_BE_FOUND: Int = 2
        const val RFC_SESSION_DOES_NOT_CONTAIN_A_CHALLENGE: Int = 3
        const val RFC_SESSION_DOES_NOT_CONTAIN_A_RESPONSE: Int = 4
        const val RFC_SESSION_DOES_NOT_CONTAIN_A_NONCE: Int = 5
        const val RFC_IDENTITY_NOT_FOUND: Int = 6
        const val RFC_INVALID_SESSION: Int = 7
    }
}
