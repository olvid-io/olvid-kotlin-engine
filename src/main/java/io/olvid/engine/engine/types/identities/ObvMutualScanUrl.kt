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
package io.olvid.engine.engine.types.identities

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvBase64.Companion.decode
import io.olvid.engine.datatypes.ObvBase64.Companion.encode
import io.olvid.engine.encoder.Encoded
import java.util.regex.Matcher
import java.util.regex.Pattern


class ObvMutualScanUrl(@JvmField val identity: Identity, @JvmField val displayName: String, @JvmField val signature: ByteArray) {
    fun getBytesIdentity(): ByteArray? {
        return identity.getBytes()
    }

    fun getUrlRepresentation(): String {
        return URL_PROTOCOL + "://" + URL_INVITATION_HOST + "/2#" + encode(
            Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(identity),
                    Encoded.of(displayName),
                    Encoded.of(signature),
                )
            ).bytes
        )
    }

    companion object {
        const val URL_PROTOCOL: String = "https"
        const val URL_PROTOCOL_OLVID: String = "olvid"
        const val URL_INVITATION_HOST: String = "invitation.olvid.io"

        val MUTUAL_SCAN_PATTERN: Pattern = Pattern.compile(
            "(" + URL_PROTOCOL + "|" + URL_PROTOCOL_OLVID + ")" + Pattern.quote("://" + URL_INVITATION_HOST) + "/2#([-_a-zA-Z0-9]+)"
        )


        fun fromUrlRepresentation(urlRepresentation: String): ObvMutualScanUrl? {
            val matcher: Matcher = MUTUAL_SCAN_PATTERN.matcher(urlRepresentation)
            if (matcher.find()) {
                try {
                    val list: Array<Encoded> = Encoded(decode(matcher.group(2))).decodeList()
                    val identity = list[0].decodeIdentity()
                    val displayName = list[1].decodeString()
                    val signature = list[2].decodeBytes()
                    return ObvMutualScanUrl(identity, displayName, signature)
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                }
            }
            return null
        }
    }
}
