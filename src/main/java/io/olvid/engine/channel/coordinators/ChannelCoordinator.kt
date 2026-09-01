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
package io.olvid.engine.channel.coordinators

import io.olvid.engine.Logger
import io.olvid.engine.channel.databases.ObliviousChannel
import io.olvid.engine.channel.datatypes.AsymmetricChannel
import io.olvid.engine.channel.datatypes.ChannelManagerSession
import io.olvid.engine.channel.datatypes.ChannelManagerSessionFactory
import io.olvid.engine.channel.datatypes.ChannelReceivedApplicationMessage
import io.olvid.engine.channel.datatypes.ChannelReceivedMessage
import io.olvid.engine.channel.datatypes.PreKeyChannel
import io.olvid.engine.datatypes.containers.AuthEncKeyAndChannelInfo
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.ProtocolReceivedMessage
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.engine.types.identities.ObvContactActiveOrInactiveReason
import java.sql.SQLException


class ChannelCoordinator(private val channelManagerSessionFactory: ChannelManagerSessionFactory) {
    fun decryptAndProcess(networkReceivedMessage: NetworkReceivedMessage) {
        try {
            channelManagerSessionFactory.session!!.use { channelManagerSession ->
                channelManagerSession.session.startTransaction()
                // try to decrypt with an ObliviousChannel
                var authEncKeyAndChannelInfo: AuthEncKeyAndChannelInfo? =
                    ObliviousChannel.unwrapMessageKey(
                        channelManagerSession,
                        networkReceivedMessage.getHeader()
                    )
                if (authEncKeyAndChannelInfo != null) {
                    Logger.d("The message can be decrypted through an ObliviousChannel.")
                    // the message was encrypted using an ObliviousChannel -> we do the processing ourselves
                    decryptAndProcess(
                        channelManagerSession,
                        networkReceivedMessage,
                        authEncKeyAndChannelInfo
                    )
                    channelManagerSession.session.commit()
                    return
                }

                // try to decrypt with a PreKey
                authEncKeyAndChannelInfo = PreKeyChannel.unwrapMessageKey(
                    channelManagerSession,
                    networkReceivedMessage.getHeader()
                )
                if (authEncKeyAndChannelInfo != null) {
                    Logger.d("The message can be decrypted with a PreKey. ")
                    decryptAndProcess(
                        channelManagerSession,
                        networkReceivedMessage,
                        authEncKeyAndChannelInfo
                    )
                    channelManagerSession.session.commit()
                    return
                }

                // try to decrypt with an AsymmetricChannel
                authEncKeyAndChannelInfo = AsymmetricChannel.unwrapMessageKey(
                    channelManagerSession,
                    networkReceivedMessage.getHeader()
                )
                if (authEncKeyAndChannelInfo != null) {
                    Logger.d("The message can be decrypted through an AsymmetricChannel.")
                    decryptAndProcess(
                        channelManagerSession,
                        networkReceivedMessage,
                        authEncKeyAndChannelInfo
                    )
                    channelManagerSession.session.commit()
                    return
                }

                // we were not able to decrypt the message -> we delete it
                if (channelManagerSession.networkFetchDelegate != null) {
                    Logger.d("The message cannot be decrypted.")
                    channelManagerSession.networkFetchDelegate.messageCannotBeDecrypted(
                        channelManagerSession.session,
                        networkReceivedMessage.ownedIdentity,
                        networkReceivedMessage.getMessageUid()
                    )
                    channelManagerSession.session.commit()
                } else {
                    Logger.w("Unable to delete a networkReceivedMessage because the NetworkFetchDelegate is not set yet.")
                }
            }
        } catch (_: SQLException) {
            Logger.i("Unable to decryptAndProcess networkReceivedMessage with uid " + networkReceivedMessage.getMessageUid())
        }
    }


    private fun decryptAndProcess(
        channelManagerSession: ChannelManagerSession,
        networkReceivedMessage: NetworkReceivedMessage,
        authEncKeyAndChannelInfo: AuthEncKeyAndChannelInfo
    ) {
        if (channelManagerSession.networkFetchDelegate == null) {
            return
        }
        val channelReceivedMessage: ChannelReceivedMessage?
        try {
            channelReceivedMessage = ChannelReceivedMessage(
                networkReceivedMessage,
                authEncKeyAndChannelInfo.getAuthEncKey()!!,
                authEncKeyAndChannelInfo.getReceptionChannelInfo()
            )
        } catch (_: Exception) {
            channelManagerSession.networkFetchDelegate.deleteMessageAndAttachments(
                channelManagerSession.session,
                networkReceivedMessage.ownedIdentity,
                networkReceivedMessage.getMessageUid()
            )
            return
        }

        // for preKey encrypted messages, check that the contact exists, otherwise, put the message on hold until the contact is added
        if (channelReceivedMessage.receptionChannelInfo
                !!.getChannelType() == ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE
        ) {
            val ownedIdentity = networkReceivedMessage.ownedIdentity
            val contactIdentity =
                channelReceivedMessage.receptionChannelInfo.getRemoteIdentity()
            if (ownedIdentity != contactIdentity) {
                try {
                    // the message is from a contact
                    if (!channelManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                            channelManagerSession.session,
                            ownedIdentity,
                            contactIdentity
                        )
                    ) {
                        // contact unknown, set the "from" identity of the inbox message to reprocess it once the contact is created
                        Logger.i("Received a PreKey encrypted message from an unknown contact, putting it on hold...")
                        channelManagerSession.networkFetchDelegate.setInboxMessageFromIdentityForMissingPreKeyContact(
                            channelManagerSession.session,
                            networkReceivedMessage.ownedIdentity,
                            networkReceivedMessage.getMessageUid(),
                            contactIdentity
                        )
                        return
                    } else {
                        val reasons =
                            channelManagerSession.identityDelegate.getContactActiveOrInactiveReasons(
                                channelManagerSession.session,
                                ownedIdentity,
                                contactIdentity
                            )
                        if (reasons != null && reasons.contains(ObvContactActiveOrInactiveReason.REVOKED) && !reasons.contains(
                                ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED
                            )
                        ) {
                            // the contact is blocked, discard the message
                            Logger.w("Received a PreKey encrypted message from a blocked contact, discarding it!")
                            channelManagerSession.networkFetchDelegate.deleteMessageAndAttachments(
                                channelManagerSession.session,
                                networkReceivedMessage.ownedIdentity,
                                networkReceivedMessage.getMessageUid()
                            )
                            return
                        } else if (!channelManagerSession.identityDelegate.isContactDeviceKnown(
                                channelManagerSession.session,
                                ownedIdentity,
                                contactIdentity,
                                channelReceivedMessage.receptionChannelInfo
                                    .getRemoteDeviceUid()
                            )
                        ) {
                            channelManagerSession.protocolStarterDelegate!!.startDeviceDiscoveryProtocolWithinTransaction(
                                channelManagerSession.session,
                                ownedIdentity,
                                contactIdentity
                            )
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }

        when (channelReceivedMessage.messageType) {
            MessageType.PROTOCOL_MESSAGE_TYPE -> {
                if (channelManagerSession.protocolDelegate == null) {
                    Logger.w("Received a protocol message, but no ProtocolDelegate is set.")
                    return
                }
                try {
                    val protocolReceivedMessage = ProtocolReceivedMessage.of(channelReceivedMessage)
                    channelManagerSession.protocolDelegate.process(
                        channelManagerSession.session,
                        protocolReceivedMessage
                    )
                } catch (_: Exception) {
                    Logger.i("Error while processing a ProtocolReceivedMessage.")
                } finally {
                    channelManagerSession.networkFetchDelegate.deleteMessageAndAttachments(
                        channelManagerSession.session,
                        networkReceivedMessage.ownedIdentity,
                        networkReceivedMessage.getMessageUid()
                    )
                }
            }

            MessageType.APPLICATION_MESSAGE_TYPE -> try {
                val channelReceivedApplicationMessage: ChannelReceivedApplicationMessage? =
                    ChannelReceivedApplicationMessage.of(channelReceivedMessage)
                if (channelReceivedApplicationMessage == null) {
                    Logger.e("Error parsing a ChannelReceivedMessage, deleting it")
                    channelManagerSession.networkFetchDelegate.deleteMessageAndAttachments(
                        channelManagerSession.session,
                        networkReceivedMessage.ownedIdentity,
                        networkReceivedMessage.getMessageUid()
                    )
                    return
                }

                channelManagerSession.networkFetchDelegate.setAttachmentKeyAndMetadataAndMessagePayload(
                    channelManagerSession.session,
                    channelReceivedApplicationMessage.ownedIdentity,
                    channelReceivedApplicationMessage.messageUid,
                    authEncKeyAndChannelInfo.getReceptionChannelInfo()!!.getRemoteIdentity(),
                    authEncKeyAndChannelInfo.getReceptionChannelInfo()!!.getRemoteDeviceUid(),
                    channelReceivedApplicationMessage.attachmentsKeyAndMetadata,
                    channelReceivedApplicationMessage.messagePayload,
                    channelReceivedMessage.extendedPayloadKey
                )
            } catch (e: Exception) {
                Logger.x(e)
                Logger.i("Error while processing a ChannelReceivedApplicationMessage.")
                channelManagerSession.networkFetchDelegate.deleteMessageAndAttachments(
                    channelManagerSession.session,
                    networkReceivedMessage.ownedIdentity,
                    networkReceivedMessage.getMessageUid()
                )
            }

            else -> Logger.w("The ChannelReceivedMessage contains an unknown MessageType: " + channelReceivedMessage.messageType)
        }
    }
}
