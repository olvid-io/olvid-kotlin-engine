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
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.RestoreFinishedCallback
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.SerializationContext

class ObvSyncSnapshot private constructor(private val snapshotMap: HashMap<String?, ObvSyncSnapshotNode?>) {
    @Throws(Exception::class)
    fun restoreOwnedIdentity(
        obvOwnedIdentity: ObvIdentity?,
        vararg delegates: ObvBackupAndSyncDelegate
    ): MutableList<RestoreFinishedCallback> {
        val callbacks: MutableList<RestoreFinishedCallback> = ArrayList<RestoreFinishedCallback>()
        try {
            for (delegate in delegates) {
                val node = snapshotMap.get(delegate.tag)
                if (node == null) {
                    throw Exception()
                }
                val callback = delegate.restoreOwnedIdentity(obvOwnedIdentity, node)
                if (callback != null) {
                    callbacks.add(callback)
                }
            }
            return callbacks
        } catch (e: Exception) {
            // if an exception occurs, call the onRestoreFailure of all callbacks we already got (typically to rollback transactions)
            for (callback in callbacks) {
                try {
                    callback.onRestoreFailure()
                } catch (_: Exception) {
                }
            }
            throw e
        }
    }

    @Throws(Exception::class)
    fun restore(vararg delegates: ObvBackupAndSyncDelegate): MutableList<RestoreFinishedCallback> {
        val callbacks: MutableList<RestoreFinishedCallback> = ArrayList()
        try {
            for (delegate in delegates) {
                val node = snapshotMap.get(delegate.tag) ?: throw Exception()
                val callback = delegate.restoreSyncSnapshot(node)
                if (callback != null) {
                    callbacks.add(callback)
                }
            }
            return callbacks
        } catch (e: Exception) {
            // if an exception occurs, call the onRestoreFailure of all callbacks we already got (typically to rollback transactions)
            for (callback in callbacks) {
                try {
                    callback.onRestoreFailure()
                } catch (_: Exception) { }
            }
            throw e
        }
    }

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
                    Encoded.of(delegate.serialize(SerializationContext.PROFILE, node)!!)
                )
            }
            return map
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }


    fun areContentsTheSame(otherSnapshot: ObvSyncSnapshot?): Boolean {
        if (otherSnapshot == null) {
            return false
        }
        if (snapshotMap.keys != otherSnapshot.snapshotMap.keys) {
            return false
        }
        for (entry in snapshotMap.entries) {
            if (!entry.value!!.areContentsTheSame(otherSnapshot.snapshotMap.get(entry.key))) {
                return false
            }
        }
        return true
    }

    @Throws(Exception::class)
    fun computeDiff(otherSnapshot: ObvSyncSnapshot): MutableList<ObvSyncDiff?> {
        if (snapshotMap.keys != otherSnapshot.snapshotMap.keys) {
            throw Exception()
        }

        val diffs: MutableList<ObvSyncDiff?> = ArrayList<ObvSyncDiff?>()
        for (entry in snapshotMap.entries) {
            diffs.addAll(entry.value!!.computeDiff(otherSnapshot.snapshotMap.get(entry.key))!!)
        }

        return diffs
    }

    fun getSnapshotNode(tag: String?): ObvSyncSnapshotNode? {
        return snapshotMap.get(tag)
    }

    companion object {
        fun get(
            ownedIdentity: Identity?,
            vararg delegates: ObvBackupAndSyncDelegate
        ): ObvSyncSnapshot {
            val snapshotMap = HashMap<String?, ObvSyncSnapshotNode?>()
            for (delegate in delegates) {
                snapshotMap.put(delegate.tag, delegate.getSyncSnapshot(ownedIdentity))
            }
            return ObvSyncSnapshot(snapshotMap)
        }


        fun fromEncodedDictionary(
            map: HashMap<DictionaryKey, Encoded>,
            vararg delegates: ObvBackupAndSyncDelegate
        ): ObvSyncSnapshot? {
            try {
                val snapshotMap = HashMap<String?, ObvSyncSnapshotNode?>()
                for (delegate in delegates) {
                    val encodedNode = map.get(DictionaryKey(delegate.tag!!))
                    if (encodedNode == null) {
                        return null
                    }
                    snapshotMap.put(
                        delegate.tag,
                        delegate.deserialize(
                            SerializationContext.PROFILE,
                            encodedNode.decodeBytes()
                        )
                    )
                }
                return ObvSyncSnapshot(snapshotMap)
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }
    }
}
