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
package io.olvid.engine.engine.types.sync

class ObvSyncDiff(
    private val diffType: Int,
    private val localBoolean: Boolean?,
    private val otherBoolean: Boolean?,
    private val localString: String?,
    private val otherString: String?
) {
    private var resolutionInProgress = false

    fun markResolutionInProgress() {
        this.resolutionInProgress = true
    }

    companion object {
        // only used to notify the app, needs to be encodable to send to other device
        const val TYPE_SETTING_AUTO_JOIN_GROUPS: Int = 0
        const val TYPE_SETTING_SEND_READ_RECEIPT: Int = 1
        const val TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION: Int = 2

        @JvmStatic fun createSettingAutoJoinGroups(localValue: String?, otherValue: String?): ObvSyncDiff {
            return ObvSyncDiff(TYPE_SETTING_AUTO_JOIN_GROUPS, null, null, localValue, otherValue)
        }

        @JvmStatic fun createSettingSendReadReceipt(localValue: Boolean, otherValue: Boolean): ObvSyncDiff {
            return ObvSyncDiff(TYPE_SETTING_SEND_READ_RECEIPT, localValue, otherValue, null, null)
        }

        @JvmStatic fun createUnarchiveOnNotification(localValue: Boolean, otherValue: Boolean): ObvSyncDiff {
            return ObvSyncDiff(
                TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION,
                localValue,
                otherValue,
                null,
                null
            )
        }
    }
}
