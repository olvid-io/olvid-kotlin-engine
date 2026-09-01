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
package io.olvid.engine.protocol.protocol_engine

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession


abstract class ProtocolStep(
    expectedReceptionChannelInfo: ReceptionChannelInfo,
    receivedMessage: ConcreteProtocolMessage,
    protocol: ConcreteProtocol
) : Operation() {
    protected val protocol: ConcreteProtocol
    var endState: ConcreteProtocolState? = null
        private set

    init {
        val rcInfo = receivedMessage.receptionChannelInfo!!
        if (expectedReceptionChannelInfo.getChannelType() == ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_OR_PRE_KEY_WITH_OWNED_DEVICE_TYPE) {
            if ((rcInfo.getChannelType() != ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE && rcInfo.getChannelType() != ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE) ||
                (rcInfo.getRemoteIdentity() != protocol.ownedIdentity)
            ) {
                Logger.d("Protocol expected ReceptionChannelInfo mismatch.")
                throw Exception()
            }
        } else if (expectedReceptionChannelInfo.getChannelType() == ReceptionChannelInfo.ANY_OBLIVIOUS_OR_PRE_KEY_CHANNEL_TYPE) {
            if (rcInfo.getChannelType() != ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE && rcInfo.getChannelType() != ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE) {
                Logger.d("Protocol expected ReceptionChannelInfo mismatch.")
                throw Exception()
            }
        } else if (expectedReceptionChannelInfo.getChannelType() == ReceptionChannelInfo.ANY_OBLIVIOUS_CHANNEL_TYPE) {
            if (rcInfo.getChannelType() != ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE) {
                Logger.d("Protocol expected ReceptionChannelInfo mismatch.")
                throw Exception()
            }
        } else if (!rcInfo.equals(expectedReceptionChannelInfo)) {
            Logger.d("Protocol expected ReceptionChannelInfo mismatch.")
            throw Exception()
        }
        this.protocol = protocol
    }

    override fun doCancel() {
        // Nothing special to do
    }

    override fun doExecute() {
        try {
            endState = executeStep()
            setFinished()
        } catch (e: Exception) {
            cancel(null)
            Logger.x(e)
        }
    }

    val ownedIdentity: Identity
        get() = protocol.ownedIdentity!!
    val jsonObjectMapper: ObjectMapper
        get() = protocol.jsonObjectMapper

    val protocolManagerSession: ProtocolManagerSession?
        get() = protocol.protocolManagerSession

    val prng: PRNGService
        get() = protocol.prng

    val protocolInstanceUid: UID?
        get() = protocol.protocolInstanceUid

    val protocolId: Int
        get() = protocol.protocolId

    @Throws(Exception::class)
    abstract fun executeStep(): ConcreteProtocolState?

    fun buildCoreProtocolMessage(sendChannelInfo: SendChannelInfo?): CoreProtocolMessage {
        return CoreProtocolMessage(sendChannelInfo, this.protocolId, this.protocolInstanceUid)
    }
}
