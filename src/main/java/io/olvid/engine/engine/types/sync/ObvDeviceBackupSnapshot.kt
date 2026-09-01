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
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.SerializationContext

class ObvDeviceBackupSnapshot private constructor(private val snapshotMap: HashMap<String?, ObvSyncSnapshotNode?>) {
    fun toEncodedDictionary(vararg delegates: ObvBackupAndSyncDelegate): HashMap<DictionaryKey, Encoded>? {
        try {
            val map = HashMap<DictionaryKey, Encoded>()
            for (delegate in delegates) {
                val node = snapshotMap.get(delegate.tag)
                if (node == null) {
                    return null
                }
                map.put(
                    DictionaryKey(delegate.tag!!),
                    Encoded.of(delegate.serialize(SerializationContext.DEVICE, node)!!)
                )
            }
            return map
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    fun getSnapshotNode(tag: String?): ObvSyncSnapshotNode? {
        return snapshotMap.get(tag)
    }

    companion object {
        fun get(vararg delegates: ObvBackupAndSyncDelegate): ObvDeviceBackupSnapshot {
            val snapshotMap = HashMap<String?, ObvSyncSnapshotNode?>()
            for (delegate in delegates) {
                snapshotMap.put(delegate.tag, delegate.getDeviceSnapshot())
            }
            return ObvDeviceBackupSnapshot(snapshotMap)
        }


        fun fromEncodedDictionary(
            map: HashMap<DictionaryKey, Encoded>,
            vararg delegates: ObvBackupAndSyncDelegate
        ): ObvDeviceBackupSnapshot? {
            try {
                val snapshotMap = HashMap<String?, ObvSyncSnapshotNode?>()
                for (delegate in delegates) {
                    val encodedNode = map.get(DictionaryKey(delegate.tag!!))
                    if (encodedNode == null) {
                        return null
                    }
                    snapshotMap.put(
                        delegate.tag,
                        delegate.deserialize(SerializationContext.DEVICE, encodedNode.decodeBytes())
                    )
                }
                return ObvDeviceBackupSnapshot(snapshotMap)
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }
    }
}
