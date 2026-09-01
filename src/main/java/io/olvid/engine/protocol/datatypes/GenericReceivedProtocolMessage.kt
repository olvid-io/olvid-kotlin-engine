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
package io.olvid.engine.protocol.datatypes

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ProtocolReceivedDialogResponse
import io.olvid.engine.datatypes.containers.ProtocolReceivedMessage
import io.olvid.engine.datatypes.containers.ProtocolReceivedServerResponse
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.util.UUID


class GenericReceivedProtocolMessage internal constructor(
    @JvmField val toIdentity: Identity?,
    @JvmField val inputs: Array<Encoded>?,
    @JvmField val userDialogUuid: UUID?,
    @JvmField val encodedResponse: Encoded?,
    @JvmField val protocolInstanceUid: UID?,
    @JvmField val protocolMessageId: Int,
    @JvmField val protocolId: Int,
    @JvmField val receptionChannelInfo: ReceptionChannelInfo?,
    @JvmField val serverTimestamp: Long,
    // version (= creation timestamp) of the dialog a dialog-response was answering. 0 otherwise.
    @JvmField val userDialogVersion: Long = 0
) {
    companion object {
        @JvmStatic
        fun of(protocolReceivedMessage: ProtocolReceivedMessage): GenericReceivedProtocolMessage? {
            try {
                val listOfEncoded: Array<Encoded> =
                    protocolReceivedMessage.getEncodedElements()!!.decodeList()
                if (listOfEncoded.size != 4) {
                    return null
                }
                val protocolId = listOfEncoded[0].decodeLong().toInt()
                val protocolInstanceUid = listOfEncoded[1].decodeUid()
                val protocolMessageId = listOfEncoded[2].decodeLong().toInt()
                val inputs: Array<Encoded> = listOfEncoded[3].decodeList()
                return GenericReceivedProtocolMessage(
                    protocolReceivedMessage.getOwnedIdentity(),
                    inputs,
                    null,
                    null,
                    protocolInstanceUid,
                    protocolMessageId,
                    protocolId,
                    protocolReceivedMessage.getReceptionChannelInfo(),
                    protocolReceivedMessage.getServerTimestamp()
                )
            } catch (_: DecodingException) {
                return null
            }
        }

        fun of(protocolReceivedDialogResponse: ProtocolReceivedDialogResponse): GenericReceivedProtocolMessage? {
            try {
                val listOfEncoded: Array<Encoded> =
                    protocolReceivedDialogResponse.getEncodedElements()!!.decodeList()
                if (listOfEncoded.size != 4) {
                    return null
                }
                val protocolId = listOfEncoded[0].decodeLong().toInt()
                val protocolInstanceUid = listOfEncoded[1].decodeUid()
                val protocolMessageId = listOfEncoded[2].decodeLong().toInt()
                val inputs: Array<Encoded> = listOfEncoded[3].decodeList()
                return GenericReceivedProtocolMessage(
                    protocolReceivedDialogResponse.getToIdentity(),
                    inputs,
                    protocolReceivedDialogResponse.getUserDialogUuid(),
                    protocolReceivedDialogResponse.getUserDialogResponse(),
                    protocolInstanceUid,
                    protocolMessageId,
                    protocolId,
                    protocolReceivedDialogResponse.getReceptionChannelInfo(),
                    0,
                    protocolReceivedDialogResponse.getUserDialogVersion()
                )
            } catch (_: DecodingException) {
                return null
            }
        }

        fun of(protocolReceivedServerResponse: ProtocolReceivedServerResponse): GenericReceivedProtocolMessage? {
            try {
                val listOfEncoded: Array<Encoded> =
                    protocolReceivedServerResponse.getEncodedElements()!!.decodeList()
                if (listOfEncoded.size != 4) {
                    return null
                }
                val protocolId = listOfEncoded[0].decodeLong().toInt()
                val protocolInstanceUid = listOfEncoded[1].decodeUid()
                val protocolMessageId = listOfEncoded[2].decodeLong().toInt()
                val inputs: Array<Encoded> = listOfEncoded[3].decodeList()
                return GenericReceivedProtocolMessage(
                    protocolReceivedServerResponse.getToIdentity(),
                    inputs,
                    null,
                    protocolReceivedServerResponse.getServerResponse(),
                    protocolInstanceUid,
                    protocolMessageId,
                    protocolId,
                    protocolReceivedServerResponse.getReceptionChannelInfo(),
                    0
                )
            } catch (_: DecodingException) {
                return null
            }
        }
    }
}
