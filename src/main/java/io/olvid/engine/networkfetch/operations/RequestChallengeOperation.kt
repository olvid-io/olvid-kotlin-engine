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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory


internal class RequestChallengeOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity
) : Operation(
    ownedIdentity.computeUniqueUid(), null, null
) {
    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        var serverSession: ServerSession?
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    serverSession = ServerSession.get(fetchManagerSession, ownedIdentity)

                    if (serverSession == null) {
                        serverSession =
                            ServerSession.create(fetchManagerSession, ownedIdentity)
                        if (serverSession == null) {
                            cancel(null)
                            return
                        }
                        fetchManagerSession.session.commit()
                    }
                    if (serverSession.challenge != null) {
                        finished = true
                        return
                    }

                    val prng = Suite.getPRNGService(PRNG.PRNG_HMAC_SHA256)
                    val nonce = prng.bytes(Constants.SERVER_SESSION_NONCE_LENGTH)


                    if (cancelWasRequested()) {
                        return
                    }

                    val serverMethod = RequestChallengeServerMethod(
                        ownedIdentity,
                        nonce
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        fetchManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    )

                    fetchManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            serverSession.setChallengeAndNonce(serverMethod.challenge, nonce)
                            finished = true
                            return
                        }

                        else -> {
                            cancel(CreateServerSessionCompositeOperation.RFC_NETWORK_ERROR)
                            return
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                    fetchManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        fetchManagerSession.session.commit()
                        setFinished()
                    } else {
                        if (hasNoReasonForCancel()) {
                            cancel(null)
                        }
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

internal class RequestChallengeServerMethod(
    private val identity: Identity,
    private val nonce: ByteArray
) : ServerMethod() {
    private val server: String

    var challenge: ByteArray? = null
        private set

    init {
        this.server = identity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(nonce),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                val challenge = receivedData!![0]!!.decodeBytes()
                val serverNonce = receivedData[1]!!.decodeBytes()
                if (!nonce.contentEquals(serverNonce) ||
                    (challenge.size != Constants.SERVER_SESSION_CHALLENGE_LENGTH)
                ) {
                    returnStatus = GENERAL_ERROR
                    return
                }
                this.challenge = challenge
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }

    override fun isActiveIdentityRequired(): Boolean {
        return false
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/requestChallenge"
    }
}