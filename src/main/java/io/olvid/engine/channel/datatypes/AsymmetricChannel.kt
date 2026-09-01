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
package io.olvid.engine.channel.datatypes

import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AuthEncKeyAndChannelInfo
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.MessageToSend
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.metamanager.EncryptionForIdentityDelegate
import java.sql.SQLException


class AsymmetricChannel(
    private val toDeviceUid: UID?,
    private val toIdentity: Identity?,
    private val encryptionForIdentityDelegate: EncryptionForIdentityDelegate?
) : NetworkChannel() {
    override fun wrapMessageKey(
        messageKey: AuthEncKey?,
        prng: PRNGService?,
        partOfFullRatchetProtocol: Boolean
    ): MessageToSend.Header? {
        if (encryptionForIdentityDelegate == null) {
            return null
        }
        val wrappedKey = encryptionForIdentityDelegate.wrap(messageKey, toIdentity, prng)
        return MessageToSend.Header(toDeviceUid, toIdentity, wrappedKey)
    }


    companion object {
        @Throws(SQLException::class)
        fun unwrapMessageKey(
            channelManagerSession: ChannelManagerSession,
            header: NetworkReceivedMessage.Header
        ): AuthEncKeyAndChannelInfo? {
            if (channelManagerSession.encryptionForIdentityDelegate == null) {
                return null
            }
            val messageKey = channelManagerSession.encryptionForIdentityDelegate.unwrap(
                channelManagerSession.session,
                header.getWrappedKey(),
                header.getOwnedIdentity()
            )
            if (messageKey == null) {
                return null
            }
            return AuthEncKeyAndChannelInfo(messageKey, ReceptionChannelInfo.createAsymmetricChannelInfo())
        }


        fun acceptableChannelsForPosting(
            message: ChannelMessageToSend,
            encryptionForIdentityDelegate: EncryptionForIdentityDelegate?
        ): Array<AsymmetricChannel?> {
            if (message.messageType != MessageType.PROTOCOL_MESSAGE_TYPE) {
                // Only protocol messages may be sent through ASYMMETRIC_CHANNEL_TYPE
                return arrayOfNulls<AsymmetricChannel>(0)
            }
            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.ASYMMETRIC_CHANNEL_TYPE -> {
                    val remoteDeviceUids = message.sendChannelInfo!!.getRemoteDeviceUids()
                    val channelList: MutableList<AsymmetricChannel?> =
                        ArrayList<AsymmetricChannel?>()
                    for (deviceUid in remoteDeviceUids!!) {
                        channelList.add(
                            AsymmetricChannel(
                                deviceUid,
                                message.sendChannelInfo!!.getToIdentity(),
                                encryptionForIdentityDelegate
                            )
                        )
                    }
                    return channelList.toTypedArray<AsymmetricChannel?>()
                }

                SendChannelInfo.ASYMMETRIC_BROADCAST_CHANNEL_TYPE -> return arrayOf<AsymmetricChannel?>(
                    AsymmetricChannel(
                        Constants.BROADCAST_UID,
                        message.sendChannelInfo!!.getToIdentity(),
                        encryptionForIdentityDelegate
                    )
                )

                else -> return arrayOfNulls<AsymmetricChannel>(0)
            }
        }
    }
}
