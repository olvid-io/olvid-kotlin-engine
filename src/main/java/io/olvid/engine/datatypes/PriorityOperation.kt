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
package io.olvid.engine.datatypes


abstract class PriorityOperation(
    uid: UID?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(uid, onFinishCallback, onCancelCallback), Comparable<PriorityOperation?> {
    override fun compareTo(other: PriorityOperation?): Int {
        if (other == null) {
            return -1
        }
        if (this.getPriority() < other.getPriority()) {
            return -1
        } else if (this.getPriority() == other.getPriority()) {
            return 0
        }
        return 1
    }

    abstract fun getPriority(): Long
}
