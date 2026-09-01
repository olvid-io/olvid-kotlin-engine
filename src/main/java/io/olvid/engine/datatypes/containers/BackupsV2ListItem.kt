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

import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded


class BackupsV2ListItem(@JvmField val threadId: UID?, @JvmField val version: Long, @JvmField val downloadUrl: String?) {
    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun manyOf(encoded: Encoded): BackupsV2ListItem {
            val encodeds: Array<Encoded> = encoded.decodeList()
            if (encodeds.size != 3) {
                throw DecodingException("Bad encoded list length: " + encodeds.size)
            }
            return BackupsV2ListItem(
                encodeds[0].decodeUid(),
                encodeds[1].decodeLong(),
                encodeds[2].decodeString()
            )
        }

        @JvmStatic
        @Throws(DecodingException::class)
        fun manyOf(encodeds: Array<Encoded>): MutableList<BackupsV2ListItem> {
            val list: MutableList<BackupsV2ListItem> = ArrayList<BackupsV2ListItem>()
            for (encoded in encodeds) {
                list.add(manyOf(encoded))
            }
            return list
        }
    }
    fun getThreadId(): UID? = threadId
    fun getVersion(): Long = version
    fun getDownloadUrl(): String? = downloadUrl
}
