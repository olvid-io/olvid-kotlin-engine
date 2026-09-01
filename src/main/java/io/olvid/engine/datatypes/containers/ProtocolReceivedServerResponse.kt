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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.encoder.Encoded

class ProtocolReceivedServerResponse(
    @JvmField val serverResponse: Encoded?,
    @JvmField val toIdentity: Identity?,
    @JvmField val encodedElements: Encoded?,
    @JvmField val receptionChannelInfo: ReceptionChannelInfo?
) {
    fun getServerResponse(): Encoded? = serverResponse
    fun getToIdentity(): Identity? = toIdentity
    fun getEncodedElements(): Encoded? = encodedElements
    fun getReceptionChannelInfo(): ReceptionChannelInfo? = receptionChannelInfo
}
