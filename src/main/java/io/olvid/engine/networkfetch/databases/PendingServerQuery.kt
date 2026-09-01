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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class PendingServerQuery : ObvDatabase {
    private val fetchManagerSession: FetchManagerSession

    @JvmField val uid: UID
    @JvmField val encodedQuery: Encoded
    @JvmField val creationTimestamp: Long
    @JvmField val isWebSocket: Boolean

    private constructor(
        fetchManagerSession: FetchManagerSession,
        uid: UID,
        encodedQuery: Encoded,
        webSocket: Boolean
    ) {
        this.fetchManagerSession = fetchManagerSession

        this.uid = uid
        this.encodedQuery = encodedQuery
        this.creationTimestamp = System.currentTimeMillis()
        this.isWebSocket = webSocket
    }

    private constructor(fetchManagerSession: FetchManagerSession, res: ResultSet) {
        this.fetchManagerSession = fetchManagerSession

        this.uid = UID(res.getBytes(UID_))
        this.encodedQuery = Encoded(res.getBytes(ENCODED_QUERY))
        this.creationTimestamp = res.getLong(CREATION_TIMESTAMP)
        this.isWebSocket = res.getBoolean(WEBSOCKET)
    }

    @Throws(SQLException::class)
    override fun insert() {
        fetchManagerSession.session.prepareStatement(
            "PendingServerQuery.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.setBytes(2, encodedQuery.bytes)
            statement.setLong(3, creationTimestamp)
            statement.setBoolean(4, this.isWebSocket)
            statement.executeUpdate()
            this.commitHookBits = this.commitHookBits or HOOK_BIT_INSERTED
            fetchManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        fetchManagerSession.session.prepareStatement(
            "PendingServerQuery.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
        ).use { statement ->
            statement.setBytes(1, uid.bytes)
            statement.executeUpdate()
        }
    }

    // endregion
    // region hooks
    interface PendingServerQueryListener {
        fun newPendingServerQuery(pendingServerQuery: PendingServerQuery?)
    }


    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            if (fetchManagerSession.pendingServerQueryListener != null) {
                fetchManagerSession.pendingServerQueryListener.newPendingServerQuery(this)
            }
        }
        commitHookBits = 0
    } // endregion

    companion object {
        const val TABLE_NAME: String = "server_query"

        const val UID_: String = "uid"
        const val ENCODED_QUERY: String = "encoded_query"
        const val CREATION_TIMESTAMP: String = "creation_timestamp"
        const val WEBSOCKET: String = "websocket"

        // region constructors
        fun create(
            fetchManagerSession: FetchManagerSession?,
            serverQuery: ServerQuery?,
            prng: PRNGService
        ): PendingServerQuery? {
            if (serverQuery == null) {
                return null
            }
            try {
                val encodedQuery = serverQuery.encode()
                val uid = UID(prng)
                val pendingServerQuery = PendingServerQuery(
                    fetchManagerSession!!,
                    uid,
                    encodedQuery,
                    serverQuery.isWebSocket
                )
                pendingServerQuery.insert()
                return pendingServerQuery
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
                            UID_ + " BLOB PRIMARY KEY, " +
                            ENCODED_QUERY + " BLOB NOT NULL, " +
                            CREATION_TIMESTAMP + " BIGINT NOT NULL, " +
                            WEBSOCKET + " BIT NOT NULL " +
                            " );"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 31 && newVersion >= 31) {
                Logger.d("MIGRATING `server_query` DATABASE FROM VERSION " + oldVersion + " TO 31")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE `server_query` ADD COLUMN `creation_timestamp` BIGINT NOT NULL DEFAULT " + System.currentTimeMillis())
                }
                oldVersion = 31
            }
            if (oldVersion < 37 && newVersion >= 37) {
                Logger.d("MIGRATING `server_query` DATABASE FROM VERSION " + oldVersion + " TO 36")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE `server_query` ADD COLUMN `websocket` BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 37
            }
        }

        // endregion
        // region getters
        fun get(fetchManagerSession: FetchManagerSession, uid: UID?): PendingServerQuery? {
            if (uid == null) {
                return null
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "PendingServerQuery.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + UID_ + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, uid.bytes)
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return PendingServerQuery(fetchManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }

        fun getAll(fetchManagerSession: FetchManagerSession): Array<PendingServerQuery?> {
            try {
                fetchManagerSession.session.prepareStatement(
                    "PendingServerQuery.getAll",
                    "SELECT * FROM " + TABLE_NAME + ";"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<PendingServerQuery?> =
                            ArrayList<PendingServerQuery?>()
                        while (res.next()) {
                            list.add(PendingServerQuery(fetchManagerSession, res))
                        }
                        return list.toTypedArray<PendingServerQuery?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<PendingServerQuery>(0)
            }
        }

        private const val HOOK_BIT_INSERTED: Long = 0x1
    }
}
