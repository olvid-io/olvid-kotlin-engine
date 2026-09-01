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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelDialogMessageToSend
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.notifications.ChannelNotifications
import java.sql.SQLException


class UserInterfaceChannel private constructor() : Channel() {
    @Throws(Exception::class)
    private fun doPost(
        channelManagerSession: ChannelManagerSession,
        message: ChannelMessageToSend,
        prng: PRNGService?
    ) {
        when (message.messageType) {
            MessageType.DIALOG_MESSAGE_TYPE -> {
                val channelDialogMessageToSend = message as ChannelDialogMessageToSend
                val userInfo = HashMap<String, Any>()
                userInfo[ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG_SESSION_KEY] = channelManagerSession.session
                userInfo[ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG_CHANNEL_DIALOG_MESSAGE_TO_SEND_KEY] = channelDialogMessageToSend
                channelManagerSession.notificationPostingDelegate?.postNotification(
                    ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG,
                    userInfo
                )
            }

            else -> Logger.i("Trying to post a message of type " + message.messageType + " on a UserInterfaceChannel.")
        }
    }

    companion object {
        @Throws(Exception::class)
        fun post(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend,
            prng: PRNGService?
        ): UID? {
            val userInterfaceChannels: Array<UserInterfaceChannel> =
                acceptableChannelsForPosting(channelManagerSession, message)
            if (userInterfaceChannels.size == 0) {
                Logger.i("No acceptable channels were found for posting")
                throw NoAcceptableChannelException()
            }
            for (userInterfaceChannel in userInterfaceChannels) {
                userInterfaceChannel.doPost(channelManagerSession, message, prng)
            }
            return null
        }

        @Throws(SQLException::class)
        private fun acceptableChannelsForPosting(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend
        ): Array<UserInterfaceChannel> {
            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.USER_INTERFACE_TYPE ->                 // Check that the toIdentity is an OwnedIdentity
                    if (channelManagerSession.identityDelegate!!.isOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getToIdentity(),
                            true
                        )
                        || message.sendChannelInfo!!.getToIdentity()!!.server == Constants.EPHEMERAL_IDENTITY_SERVER
                    ) {
                        return arrayOf(UserInterfaceChannel())
                    } else {
                        return emptyArray()
                    }

                else -> return emptyArray()
            }
        }
    }
}
