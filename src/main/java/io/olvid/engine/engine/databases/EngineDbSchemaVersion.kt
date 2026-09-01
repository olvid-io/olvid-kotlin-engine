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
package io.olvid.engine.engine.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.engine.datatypes.EngineSession
import java.sql.ResultSet
import java.sql.SQLException

class EngineDbSchemaVersion private constructor(private val engineSession: EngineSession, res: ResultSet) :
    ObvDatabase {

    private var version: Int
    fun getVersion(): Int {
        return version
    }

    init {
        this.version = res.getInt(VERSION)
    }

    @Throws(SQLException::class)
    fun update(version: Int) {
        engineSession.session.prepareStatement(
            "EngineDbSchemaVersion.update",
            "UPDATE " + TABLE_NAME +
                    " SET " + VERSION + " = ?;"
        ).use { statement ->
            statement.setInt(1, version)
            statement.executeUpdate()
            this.version = version
        }
    }


    @Throws(SQLException::class)
    override fun delete() {
        Logger.e("Deletion in table " + TABLE_NAME + " Is Prohibited")
        throw SQLException()
    }

    @Throws(SQLException::class)
    override fun insert() {
        Logger.e("Insertion in table " + TABLE_NAME + " Is Prohibited")
        throw SQLException()
    }

    override fun wasCommitted() {
        // Nothing to do
    }

    companion object {
        const val TABLE_NAME: String = "engine_db_schema_version"

        const val VERSION: String = "version"


        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.prepareStatement("SELECT name FROM sqlite_master WHERE type=? AND name = ?")
                .use { statement ->
                    statement.setString(1, "table")
                    statement.setString(2, TABLE_NAME)
                    statement.executeQuery().use { res ->
                        if (!res.next()) {
                            // table does not exist yet, so create it and insert the current version number
                            session.createStatement().use { createStatement ->
                                createStatement.execute("CREATE TABLE " + TABLE_NAME + " (" + VERSION + " INT NOT NULL);")
                            }
                            session.prepareStatement("INSERT INTO " + TABLE_NAME + " VALUES (?)")
                                .use { insertStatement ->
                                    insertStatement.setInt(
                                        1,
                                        Constants.CURRENT_ENGINE_DB_SCHEMA_VERSION
                                    )
                                    insertStatement.executeUpdate()
                                }
                        }
                    }
                }
        }

        fun get(engineSession: EngineSession): EngineDbSchemaVersion? {
            try {
                engineSession.session.prepareStatement(
                    "EngineDbSchemaVersion.get",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        return if (res.next()) {
                            EngineDbSchemaVersion(engineSession, res)
                        } else {
                            null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }
    }
}
