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
package io.olvid.engine.metamanager

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import java.sql.SQLException


interface PushNotificationDelegate {
    @Throws(SQLException::class)
    fun registerPushNotificationIfConfigurationChanged(
        session: Session,
        ownedIdentity: Identity?,
        currentDeviceUid: UID?,
        newPushParameters: PushNotificationTypeAndParameters?
    )

    fun processAndroidPushNotification(maskingUidString: String?)
    fun forceRegisterPushNotification(
        ownedIdentity: Identity?,
        triggerAnOwnedDeviceDiscoveryWhenFinished: Boolean
    )

    fun getOwnedIdentityFromMaskingUid(maskingUidString: String?): Identity?
}
