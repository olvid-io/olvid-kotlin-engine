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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.metamanager.SolveChallengeDelegate
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException

class SolveChallengeOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    @JvmField val identity: Identity,
    private val solveChallengeDelegate: SolveChallengeDelegate
) : Operation(
    identity.computeUniqueUid(), null, null
) {
    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        val serverSession: ServerSession?
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    serverSession = ServerSession.get(fetchManagerSession, identity)

                    if (serverSession == null) {
                        cancel(CreateServerSessionCompositeOperation.RFC_SESSION_CANNOT_BE_FOUND)
                        return
                    }
                    if (serverSession.response != null || serverSession.token != null) {
                        finished = true
                        return
                    }
                    if (serverSession.challenge == null) {
                        cancel(CreateServerSessionCompositeOperation.RFC_SESSION_DOES_NOT_CONTAIN_A_CHALLENGE)
                        return
                    }

                    val prng = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)
                    val response: ByteArray?
                    try {
                        response = solveChallengeDelegate.solveChallenge(
                            serverSession.challenge!!,
                            identity,
                            prng
                        )
                    } catch (_: Exception) {
                        cancel(CreateServerSessionCompositeOperation.RFC_IDENTITY_NOT_FOUND)
                        return
                    }

                    fetchManagerSession.session.startTransaction()
                    serverSession.setResponseForChallenge(serverSession.challenge, response)

                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                    fetchManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        fetchManagerSession.session.commit()
                        setFinished()
                    } else {
                        cancel(null)
                        processCancel()
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            cancel(null)
            processCancel()
        }
    }
}
