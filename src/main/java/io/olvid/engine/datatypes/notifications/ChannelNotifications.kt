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

package io.olvid.engine.datatypes.notifications

object ChannelNotifications {
    const val NOTIFICATION_NEW_UI_DIALOG = "channel_notification_new_ui_dialog"
    const val NOTIFICATION_NEW_UI_DIALOG_SESSION_KEY = "session_key" // Session
    const val NOTIFICATION_NEW_UI_DIALOG_CHANNEL_DIALOG_MESSAGE_TO_SEND_KEY = "message_to_send_key" // MessageToSend

    const val NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED = "channel_notification_channel_confirmed"
    const val NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_CURRENT_DEVICE_UID_KEY = "current_device_uid_key" // UID
    const val NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_REMOTE_IDENTITY_KEY = "remote_identity_key" // Identity
    const val NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_REMOTE_DEVICE_UID__KEY = "remote_device_uid_key" // UID

    const val NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED = "channel_notification_channel_deleted"
    const val NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_CURRENT_DEVICE_UID_KEY = "current_device_uid_key" // UID
    const val NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_REMOTE_IDENTITY_KEY = "remote_identity_key" // Identity
}
