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
package io.olvid.engine.networkfetch.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import java.sql.ResultSet
import java.sql.SQLException


class CachedWellKnown : ObvDatabase {
    private val fetchManagerSession: FetchManagerSession?

    @JvmField val server: String?
    var serializedWellKnown: String?
        private set
    var downloadTimestamp: Long
        private set

    constructor(
        fetchManagerSession: FetchManagerSession?,
        server: String?,
        serializedWellKnown: String?,
        downloadTimestamp: Long
    ) {
        this.fetchManagerSession = fetchManagerSession

        this.server = server
        this.serializedWellKnown = serializedWellKnown
        this.downloadTimestamp = downloadTimestamp
    }

    constructor(fetchManagerSession: FetchManagerSession, res: ResultSet) {
        this.fetchManagerSession = fetchManagerSession

        this.server = res.getString(SERVER)
        this.serializedWellKnown = res.getString(SERIALIZED_WELL_KNOWN)
        this.downloadTimestamp = res.getLong(DOWNLOAD_TIMESTAMP)
    }

    @Throws(SQLException::class)
    override fun insert() {
        fetchManagerSession!!.session.prepareStatement(
            "CachedWellKnown.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?);"
        ).use { statement ->
            statement.setString(1, server)
            statement.setString(2, serializedWellKnown)
            statement.setLong(3, downloadTimestamp)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        fetchManagerSession!!.session.prepareStatement(
            "CachedWellKnown.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + SERVER + " = ?;"
        ).use { statement ->
            statement.setString(1, server)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    fun update(serializedWellKnown: String?) {
        fetchManagerSession!!.session.prepareStatement(
            "CachedWellKnown.update",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_WELL_KNOWN + " = ?, " +
                    DOWNLOAD_TIMESTAMP + " = ? " +
                    " WHERE " + SERVER + " = ?;"
        ).use { statement ->
            val timestamp = System.currentTimeMillis()
            statement.setString(1, serializedWellKnown)
            statement.setLong(2, timestamp)
            statement.setString(3, server)
            statement.executeUpdate()
            this.serializedWellKnown = serializedWellKnown
            this.downloadTimestamp = timestamp
        }
    }

    // endregion
    override fun wasCommitted() {
        // no hook yet
    }

    companion object {
        const val TABLE_NAME: String = "cached_well_known"

        const val SERVER: String = "server"
        const val SERIALIZED_WELL_KNOWN: String = "serialized_well_known"
        const val DOWNLOAD_TIMESTAMP: String = "download_timestamp"

        // region getters
        fun getAll(fetchManagerSession: FetchManagerSession): MutableList<CachedWellKnown?> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "CachedWellKnown.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<CachedWellKnown?> = ArrayList<CachedWellKnown?>()
                        while (res.next()) {
                            list.add(CachedWellKnown(fetchManagerSession, res))
                        }
                        return list
                    }
                }
            } catch (_: SQLException) {
                return ArrayList<CachedWellKnown?>()
            }
        }

        @Throws(SQLException::class)
        fun get(fetchManagerSession: FetchManagerSession, server: String?): CachedWellKnown? {
            if (server == null) {
                return null
            }
            fetchManagerSession.session.prepareStatement(
                "CachedWellKnown.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + SERVER + " = ?;"
            ).use { statement ->
                statement.setString(1, server)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return CachedWellKnown(fetchManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        // endregion
        // region constructors
        fun create(
            fetchManagerSession: FetchManagerSession?,
            server: String?,
            serializedWellKnown: String?
        ): CachedWellKnown? {
            if (server == null || serializedWellKnown == null) {
                return null
            }
            try {
                val cachedWellKnown = CachedWellKnown(
                    fetchManagerSession,
                    server,
                    serializedWellKnown,
                    System.currentTimeMillis()
                )
                cachedWellKnown.insert()
                return cachedWellKnown
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }


        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            SERVER + " TEXT PRIMARY KEY, " +
                            SERIALIZED_WELL_KNOWN + " TEXT NOT NULL, " +
                            DOWNLOAD_TIMESTAMP + " BIGINT NOT NULL);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 19 && newVersion >= 19) {
                Logger.d("MIGRATING `cached_well_known` DATABASE FROM VERSION " + oldVersion + " TO 19")
                session.createStatement().use { statement ->
                    statement.execute("CREATE TABLE IF NOT EXISTS cached_well_known (server TEXT PRIMARY KEY, serialized_well_known TEXT NOT NULL, download_timestamp BIGINT NOT NULL);")
                }
                oldVersion = 19
            }
        }
    }
}
