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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.encoder.Encoded

class ObvProfileBackupSnapshot private constructor(
    private val snapshot: ObvSyncSnapshot,
    private val timestamp: Long,
    private val additional_info: MutableMap<String?, String?>
) {
    fun getAdditionalInfo(): MutableMap<String?, String?> {
        return additional_info
    }

    fun getTimestamp(): Long {
        return timestamp
    }

    fun getSnapshot(): ObvSyncSnapshot {
        return snapshot
    }

    fun toEncodedDictionary(vararg delegates: ObvBackupAndSyncDelegate?): HashMap<DictionaryKey, Encoded>? {
        try {
            val map = HashMap<DictionaryKey, Encoded>()
            @Suppress("UNCHECKED_CAST")
            map.put(DictionaryKey(SNAPSHOT), Encoded.of(snapshot.toEncodedDictionary(*(delegates as Array<ObvBackupAndSyncDelegate>))!!))
            map.put(DictionaryKey(ADDITIONAL_INFO), Encoded.of(additional_info))
            map.put(DictionaryKey(TIMESTAMP), Encoded.of(timestamp))

            return map
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    companion object {
        const val SNAPSHOT: String = "snapshot"
        const val ADDITIONAL_INFO: String = "additional_info"
        const val TIMESTAMP: String = "timestamp"

        const val INFO_PLATFORM: String = "platform"
        const val INFO_DEVICE_NAME: String = "device_name"

        fun get(
            ownedIdentity: Identity?,
            vararg delegates: ObvBackupAndSyncDelegate
        ): ObvProfileBackupSnapshot {
            val obvSyncSnapshot: ObvSyncSnapshot =
                ObvSyncSnapshot.get(ownedIdentity, *delegates)
            val additionalProfileInfo = HashMap<String?, String?>()
            for (delegate in delegates) {
                val info = delegate.getAdditionalProfileInfo(ownedIdentity)
                if (info != null) {
                    additionalProfileInfo.putAll(info)
                }
            }
            return ObvProfileBackupSnapshot(
                obvSyncSnapshot,
                System.currentTimeMillis(),
                additionalProfileInfo
            )
        }


        fun fromEncodedDictionary(
            map: HashMap<DictionaryKey, Encoded>,
            vararg delegates: ObvBackupAndSyncDelegate?
        ): ObvProfileBackupSnapshot? {
            try {
                val encodedSnapshot = map.get(DictionaryKey(SNAPSHOT))
                val encodedTimestamp = map.get(DictionaryKey(TIMESTAMP))
                val encodedAdditionalInfo = map.get(DictionaryKey(ADDITIONAL_INFO))

                if (encodedSnapshot == null || encodedTimestamp == null) {
                    return null
                }

                @Suppress("UNCHECKED_CAST")
                return ObvProfileBackupSnapshot(
                    ObvSyncSnapshot.fromEncodedDictionary(
                        encodedSnapshot.decodeDictionary(),
                        *(delegates as Array<ObvBackupAndSyncDelegate>)
                    )!!,
                    encodedTimestamp.decodeLong(),
                    if (encodedAdditionalInfo == null) HashMap<String?, String?>() else encodedAdditionalInfo.decodeStringMap()
                )
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }
    }
}
