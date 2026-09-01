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

package io.olvid.engine.datatypes

import java.util.Arrays

class PushNotificationTypeAndParameters(
    @JvmField val pushNotificationType: Byte,
    @JvmField val token: ByteArray?,
    @JvmField var identityMaskingUid: UID?,
    @JvmField var reactivateCurrentDevice: Boolean,
    @JvmField var deviceUidToReplace: UID?
) {

    companion object {
        const val PUSH_NOTIFICATION_TYPE_ANDROID: Byte = 0x01
        const val PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID: Byte = 0x10
        const val PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS: Byte = 0x11
        const val PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX: Byte = 0x12
        const val PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON: Byte = 0x13

        @JvmStatic
        fun createWebsocketOnlyAndroid(reactivateCurrentDevice: Boolean, deviceUidToReplace: UID?): PushNotificationTypeAndParameters {
            return PushNotificationTypeAndParameters(PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID, null, null, reactivateCurrentDevice, deviceUidToReplace)
        }

        @JvmStatic
        fun createWindows(reactivateCurrentDevice: Boolean, deviceUidToReplace: UID?): PushNotificationTypeAndParameters {
            return PushNotificationTypeAndParameters(PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS, null, null, reactivateCurrentDevice, deviceUidToReplace)
        }

        @JvmStatic
        fun createLinux(reactivateCurrentDevice: Boolean, deviceUidToReplace: UID?): PushNotificationTypeAndParameters {
            return PushNotificationTypeAndParameters(PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX, null, null, reactivateCurrentDevice, deviceUidToReplace)
        }

        @JvmStatic
        fun createDaemon(reactivateCurrentDevice: Boolean, deviceUidToReplace: UID?): PushNotificationTypeAndParameters {
            return PushNotificationTypeAndParameters(PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON, null, null, reactivateCurrentDevice, deviceUidToReplace)
        }

        @JvmStatic
        fun createFirebaseAndroid(token: ByteArray?, identityMaskingUid: UID?, reactivateCurrentDevice: Boolean, deviceUidToReplace: UID?): PushNotificationTypeAndParameters {
            return PushNotificationTypeAndParameters(PUSH_NOTIFICATION_TYPE_ANDROID, token, identityMaskingUid, reactivateCurrentDevice, deviceUidToReplace)
        }
    }

    fun sameTypeAndToken(other: PushNotificationTypeAndParameters?): Boolean {
        if (other == null) {
            return false
        }
        if (pushNotificationType != other.pushNotificationType) {
            return false
        }
        return when (pushNotificationType) {
            PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID,
            PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS,
            PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX,
            PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON -> true
            PUSH_NOTIFICATION_TYPE_ANDROID -> Arrays.equals(token, other.token)
            else -> false
        }
    }
}
