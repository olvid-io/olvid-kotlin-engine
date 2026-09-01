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

import org.junit.Assert.*
import org.junit.Test

class TrustLevelTest {

    @Test
    fun testConstructorAndFields() {
        val trust = TrustLevel(5, 2)
        assertEquals(5, trust.major)
        assertEquals(2, trust.minor)
    }

    @Test
    fun testOfFactory() {
        val trust = TrustLevel.of("3.4")
        assertEquals(3, trust.major)
        assertEquals(4, trust.minor)
    }

    @Test
    fun testToString() {
        val trust = TrustLevel(2, 7)
        assertEquals("2.7", trust.toString())
    }

    @Test
    fun testStaticCreators() {
        val direct = TrustLevel.createDirect()
        assertEquals(4, direct.major)
        assertEquals(0, direct.minor)

        val server = TrustLevel.createServer()
        assertEquals(3, server.major)
        assertEquals(0, server.minor)

        val indirect = TrustLevel.createIndirect(8)
        assertEquals(2, indirect.major)
        assertEquals(8, indirect.minor)

        val serverGroup = TrustLevel.createServerGroupV2()
        assertEquals(1, serverGroup.major)
        assertEquals(0, serverGroup.minor)
    }

    @Test
    fun testCompareTo() {
        val low = TrustLevel(1, 5)
        val mid1 = TrustLevel(2, 3)
        val mid2 = TrustLevel(2, 4)
        val high = TrustLevel(3, 0)

        // Compare major
        assertTrue(low.compareTo(mid1) < 0)
        assertTrue(mid1.compareTo(low) > 0)

        // Compare minor
        assertTrue(mid1.compareTo(mid2) < 0)
        assertTrue(mid2.compareTo(mid1) > 0)

        // Compare equal
        val equalMid = TrustLevel(2, 3)
        assertEquals(0, mid1.compareTo(equalMid))
    }

    @Test
    fun testJvmStaticDelegatorsViaReflection() {
        val trustLevelClass = TrustLevel::class.java

        // Test of(String)
        val ofMethod = trustLevelClass.getMethod("of", String::class.java)
        val ofResult = ofMethod.invoke(null, "4.2") as TrustLevel
        assertEquals(4, ofResult.major)
        assertEquals(2, ofResult.minor)

        // Test createDirect()
        val createDirectMethod = trustLevelClass.getMethod("createDirect")
        val directResult = createDirectMethod.invoke(null) as TrustLevel
        assertEquals(4, directResult.major)
        assertEquals(0, directResult.minor)

        // Test createServer()
        val createServerMethod = trustLevelClass.getMethod("createServer")
        val serverResult = createServerMethod.invoke(null) as TrustLevel
        assertEquals(3, serverResult.major)
        assertEquals(0, serverResult.minor)

        // Test createIndirect(int)
        val createIndirectMethod = trustLevelClass.getMethod("createIndirect", Int::class.javaPrimitiveType)
        val indirectResult = createIndirectMethod.invoke(null, 5) as TrustLevel
        assertEquals(2, indirectResult.major)
        assertEquals(5, indirectResult.minor)

        // Test createServerGroupV2()
        val createServerGroupV2Method = trustLevelClass.getMethod("createServerGroupV2")
        val groupResult = createServerGroupV2Method.invoke(null) as TrustLevel
        assertEquals(1, groupResult.major)
        assertEquals(0, groupResult.minor)
    }
}
