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
package io.olvid.engine.engine.types

class ObvPushNotificationType private constructor(platform: Platform?, firebaseToken: String?) {
    enum class Platform {
        ANDROID,
        WINDOWS,
        LINUX,
        DAEMON,
    }

    val platform: Platform?
    val firebaseToken: String?

    init {
        this.platform = platform
        this.firebaseToken = firebaseToken
    }

    companion object {
        @JvmStatic fun createAndroid(firebaseToken: String?): ObvPushNotificationType {
            return ObvPushNotificationType(Platform.ANDROID, firebaseToken)
        }

        @JvmStatic fun createWindows(): ObvPushNotificationType {
            return ObvPushNotificationType(Platform.WINDOWS, null)
        }

        @JvmStatic fun createLinux(): ObvPushNotificationType {
            return ObvPushNotificationType(Platform.LINUX, null)
        }

        @JvmStatic fun createDaemon(): ObvPushNotificationType {
            return ObvPushNotificationType(Platform.DAEMON, null)
        }
    }
}
