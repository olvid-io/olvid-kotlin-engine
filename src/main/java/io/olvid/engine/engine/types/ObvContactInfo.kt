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


class ObvContactInfo(
    bytesOwnedIdentity: ByteArray?,
    bytesContactIdentity: ByteArray?,
    identityDetails: JsonIdentityDetails?,
    keycloakManaged: Boolean,
    oneToOne: Boolean,
    photoUrl: String?,
    active: Boolean,
    recentlyOnline: Boolean,
    trustLevel: Int,
    contactDeviceCount: ObvContactDeviceCount?
) {
    @JvmField val bytesOwnedIdentity: ByteArray?
    @JvmField val bytesContactIdentity: ByteArray?
    @JvmField val identityDetails: JsonIdentityDetails?
    @JvmField val photoUrl: String?
    @JvmField val keycloakManaged: Boolean
    @JvmField val active: Boolean
    @JvmField val oneToOne: Boolean
    @JvmField val trustLevel: Int
    @JvmField val recentlyOnline: Boolean
    @JvmField val contactDeviceCount: ObvContactDeviceCount?

    init {
        this.bytesOwnedIdentity = bytesOwnedIdentity
        this.bytesContactIdentity = bytesContactIdentity
        this.identityDetails = identityDetails
        this.keycloakManaged = keycloakManaged
        this.oneToOne = oneToOne
        this.photoUrl = photoUrl
        this.active = active
        this.recentlyOnline = recentlyOnline
        this.trustLevel = trustLevel
        this.contactDeviceCount = contactDeviceCount
    }
}
