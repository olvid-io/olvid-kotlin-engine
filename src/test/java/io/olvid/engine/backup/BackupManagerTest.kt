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

package io.olvid.engine.backup

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.BackupSeed
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class BackupManagerTest {

    @Test
    fun testEquivString() {
        val mapper = ObjectMapper()
        val jsonURL = javaClass.classLoader!!.getResource("TestVectorsEquivalentBackupSeedString.json")
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL)

        val equivStrings: Array<EquivString> = mapper.readValue(jsonURL, object : TypeReference<Array<EquivString>>() {})
        for (equivString in equivStrings) {
            assertEquals(BackupSeed(equivString.backupSeedString1!!), BackupSeed(equivString.backupSeedString2!!))
        }
    }

    @Test
    fun testStringAndSeed() {
        val mapper = ObjectMapper()
        val jsonURL = javaClass.classLoader!!.getResource("TestVectorsBackupSeedFromString.json")
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL)

        val seedAndStrings: Array<SeedAndString> = mapper.readValue(jsonURL, object : TypeReference<Array<SeedAndString>>() {})
        for (seedAndString in seedAndStrings) {
            assertArrayEquals(BackupSeed(seedAndString.backupSeedString!!).backupSeedBytes, Logger.fromHexString(seedAndString.backupSeed!!))
        }
    }

    class SeedAndString {
        var backupSeed: String? = null
        var backupSeedString: String? = null
    }

    class EquivString {
        var backupSeedString1: String? = null
        var backupSeedString2: String? = null
    }
}
