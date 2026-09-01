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

class TrustLevel(
    @JvmField val major: Int,
    @JvmField val minor: Int
) : Comparable<TrustLevel> {

    companion object {
        @JvmStatic
        fun of(majorDotMinor: String): TrustLevel {
            val major = majorDotMinor.substring(0, 1).toInt()
            val minor = majorDotMinor.substring(2, 3).toInt()
            return TrustLevel(major, minor)
        }

        @JvmStatic
        fun createDirect(): TrustLevel {
            return TrustLevel(4, 0)
        }

        @JvmStatic
        fun createServer(): TrustLevel {
            return TrustLevel(3, 0)
        }

        @JvmStatic
        fun createIndirect(indirectTrustLevelMajor: Int): TrustLevel {
            return TrustLevel(2, indirectTrustLevelMajor)
        }

        @JvmStatic
        fun createServerGroupV2(): TrustLevel {
            return TrustLevel(1, 0)
        }
    }

    override fun toString(): String {
        return "$major.$minor"
    }

    override fun compareTo(other: TrustLevel): Int {
        if (major < other.major) {
            return -1
        }
        if (major > other.major) {
            return 1
        }
        return minor.compareTo(other.minor)
    }
}
