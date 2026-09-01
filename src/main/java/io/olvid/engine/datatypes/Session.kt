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

import io.olvid.engine.Logger
import io.olvid.engine.engine.types.EngineDbQueryStatisticsEntry
import io.olvid.engine.engine.types.EngineDbQueryStatisticsEntry.Companion.create
import java.io.InputStream
import java.io.Reader
import java.lang.AutoCloseable
import java.math.BigDecimal
import java.net.URL
import java.sql.Array as SqlArray
import java.sql.Blob
import java.sql.Clob
import java.sql.Connection
import java.sql.Date
import java.sql.Driver
import java.sql.DriverManager
import java.sql.NClob
import java.sql.ParameterMetaData
import java.sql.PreparedStatement
import java.sql.Ref
import java.sql.ResultSet
import java.sql.ResultSetMetaData
import java.sql.RowId
import java.sql.SQLException
import java.sql.SQLWarning
import java.sql.SQLXML
import java.sql.Statement
import java.sql.Time
import java.sql.Timestamp
import java.util.Calendar
import java.util.Properties
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock

class Session private constructor(
    dbPath: String,
    dbKey: String?,
    sessionIsForUpgradeTables: Boolean
) : AutoCloseable {
    private val connection: Connection
    private val sessionCommitListeners: MutableSet<SessionCommitListener>
    private val dbPath: String
    private val sessionIsForUpgradeTable: Boolean

    init {
        this.dbPath = dbPath
        this.sessionCommitListeners = LinkedHashSet<SessionCommitListener>()
        this.sessionIsForUpgradeTable = sessionIsForUpgradeTables
        val properties = Properties()
        properties.setProperty("secure_delete", "on")
        properties.setProperty("temp_store", "2")
        properties.setProperty("journal_mode", "WAL")
        properties.setProperty(
            "busy_timeout",
            "10000"
        ) // increase the db locked timeout as some queries may take more than 3s!
        if (dbKey != null) {
            properties.setProperty("password", dbKey)
        }
        if (sessionIsForUpgradeTables) {
            // No foreign keys and no autocommit, but legacy alter table to avoid renaming references when renaming table
            properties.setProperty("legacy_alter_table", "true")
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath, properties)
        } else {
            properties.setProperty("foreign_keys", "true")
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath, properties)
            this.connection.setAutoCommit(true)
        }
    }

    fun addSessionCommitListener(listener: SessionCommitListener?) {
        sessionCommitListeners.add(listener!!)
    }

    @get:Throws(SQLException::class)
    val isInTransaction: Boolean
        get() = !connection.getAutoCommit()

    @Throws(SQLException::class)
    fun startTransaction() {
        if (this.isInTransaction) {
            Logger.e("Starting transaction from within a transaction!")
            Logger.x(Exception("Trace"))
            return
        }
        globalWriteLock.lock()
        connection.setAutoCommit(false)
    }

    @Throws(SQLException::class)
    fun commit() {
        if (!connection.getAutoCommit()) {
            connection.commit()
            connection.setAutoCommit(true)
            globalWriteLock.unlock()
        }
        for (sessionCommitListener in sessionCommitListeners.toTypedArray<SessionCommitListener>()) {
            sessionCommitListener.wasCommitted()
        }
        sessionCommitListeners.clear()
    }

    @Throws(SQLException::class)
    fun rollback() {
        if (!connection.getAutoCommit()) {
            try {
                connection.rollback()
                connection.setAutoCommit(true)
                sessionCommitListeners.clear()
            } finally {
                globalWriteLock.unlock()
            }
        } else {
            Logger.d("Calling rollback on an autoCommit Session.")
        }
    }

    @JvmOverloads
    @Throws(SQLException::class)
    fun createStatement(tag: String? = null): Statement {
        return DeferrableStatement(tag, connection.createStatement(), this)
    }

    @Throws(SQLException::class)
    fun prepareStatement(s: String?): PreparedStatement {
        return prepareStatement(null, s)
    }

    @Throws(SQLException::class)
    fun prepareStatement(tag: String?, s: String?): PreparedStatement {
        return DeferrablePreparedStatement(tag, connection.prepareStatement(s), this)
    }

    @Throws(SQLException::class)
    fun prepareStatement(s: String?, returnGeneratedKeys: Boolean): PreparedStatement {
        return prepareStatement(null, s, returnGeneratedKeys)
    }

    @Throws(SQLException::class)
    fun prepareStatement(
        tag: String?,
        s: String?,
        returnGeneratedKeys: Boolean
    ): PreparedStatement {
        return DeferrablePreparedStatement(
            tag,
            connection.prepareStatement(
                s,
                if (returnGeneratedKeys) Statement.RETURN_GENERATED_KEYS else Statement.NO_GENERATED_KEYS
            ),
            this
        )
    }

    @Throws(SQLException::class)
    override fun close() {
        if (!sessionCommitListeners.isEmpty()) {
            Logger.e("This Session was not properly closed: some modifications were committed and the corresponding hooks have not been called.")
            for (sessionCommitListener in sessionCommitListeners) {
                Logger.e("  - Un-committed entity: " + sessionCommitListener.javaClass)
            }
            sessionCommitListeners.clear()
            Logger.x(Exception("Trace"))
        }
        if (!this.autoCommit) {
            rollback()
        }
        if (sessionIsForUpgradeTable) {
            connection.close()
        } else {
            sessionPoolLock.lock()
            var sessionList: MutableList<Session>? = sessionPool[dbPath]
            if (sessionList.isNullOrEmpty()) {
                sessionList = ArrayList<Session>()
                sessionPool[dbPath] = sessionList
            }
            sessionList.add(this)
            sessionPoolLock.unlock()
        }
    }

    @get:Throws(SQLException::class)
    val autoCommit: Boolean
        get() = connection.getAutoCommit()

    companion object {
        val queryStatistics: MutableMap<String, EngineDbQueryStatisticsEntry> =
            ConcurrentHashMap<String, EngineDbQueryStatisticsEntry>()

        val globalWriteLock: ReentrantLock = ReentrantLock()
        private val sessionPool = HashMap<String, MutableList<Session>>()
        private val sessionPoolLock = ReentrantLock()

        init {
            try {
                DriverManager.registerDriver(
                    Class.forName("org.sqlite.JDBC").getDeclaredConstructor()
                        .newInstance() as Driver
                )
            } catch (e: Exception) {
                Logger.x(e)
            }
        }

        @Throws(SQLException::class)
        fun getSession(dbPath: String, dbKey: String?): Session {
            val session: Session

            sessionPoolLock.lock()
            val sessionList: MutableList<Session>? = sessionPool[dbPath]
            if (sessionList.isNullOrEmpty()) {
                sessionPoolLock.unlock()
                session = Session(dbPath, dbKey, false)
            } else {
                session = sessionList.removeAt(0)
                sessionPoolLock.unlock()
            }
            return session
        }

        @JvmStatic @Throws(SQLException::class)
        fun getUpgradeTablesSession(dbPath: String, dbKey: String?): Session {
            return Session(dbPath, dbKey, true)
        }

        fun databaseIsReadable(dbPath: String, dbKey: String?): Boolean {
            try {
                Session(dbPath, dbKey, true).use { session ->
                    session.createStatement().use { statement ->
                        statement.execute("SELECT count(*) FROM sqlite_master;")
                    }
                    return true
                }
            } catch (_: SQLException) {
                return false
            }
        }

        fun registerQueryTime(tag: String?, timeMicro: Long) {
            if (tag == null) {
                return
            }
            queryStatistics.compute(tag) { key: String, value: EngineDbQueryStatisticsEntry? ->
                if (value == null) {
                    return@compute create(timeMicro)
                }
                value.increment(timeMicro)
            }
        }
    }
}


internal class DeferrableStatement(
    private val tag: String?,
    private val statement: Statement,
    private val session: Session
) : Statement {
    @Throws(SQLException::class)
    override fun close() {
        statement.close()
    }

    @Throws(SQLException::class)
    override fun execute(s: String?): Boolean {
        var res: Boolean
        var startTime: Long
        if (session.autoCommit) {
            try {
                Session.Companion.globalWriteLock.lock()
                startTime = System.nanoTime()
                res = statement.execute(s)
            } finally {
                Session.Companion.globalWriteLock.unlock()
            }
        } else {
            startTime = System.nanoTime()
            res = statement.execute(s)
        }
        Session.registerQueryTime(tag, (System.nanoTime() - startTime) / 1000)
        return res
    }

    @Throws(SQLException::class)
    override fun executeQuery(s: String?): ResultSet? {
        val startTime = System.nanoTime()
        val res = statement.executeQuery(s)
        Session.registerQueryTime(tag, (System.nanoTime() - startTime) / 1000)
        return res
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?): Int {
        var res: Int
        var startTime: Long
        if (session.autoCommit) {
            try {
                Session.Companion.globalWriteLock.lock()
                startTime = System.nanoTime()
                res = statement.executeUpdate(s)
            } finally {
                Session.Companion.globalWriteLock.unlock()
            }
        } else {
            startTime = System.nanoTime()
            res = statement.executeUpdate(s)
        }
        Session.registerQueryTime(tag, (System.nanoTime() - startTime) / 1000)
        return res
    }

    @Throws(SQLException::class)
    override fun getMaxFieldSize(): Int {
        return statement.getMaxFieldSize()
    }

    @Throws(SQLException::class)
    override fun setMaxFieldSize(i: Int) {
        statement.setMaxFieldSize(i)
    }

    @Throws(SQLException::class)
    override fun getMaxRows(): Int {
        return statement.getMaxRows()
    }

    @Throws(SQLException::class)
    override fun setMaxRows(i: Int) {
        statement.setMaxRows(i)
    }

    @Throws(SQLException::class)
    override fun setEscapeProcessing(b: Boolean) {
        statement.setEscapeProcessing(b)
    }

    @Throws(SQLException::class)
    override fun getQueryTimeout(): Int {
        return statement.getQueryTimeout()
    }

    @Throws(SQLException::class)
    override fun setQueryTimeout(i: Int) {
        statement.setQueryTimeout(i)
    }

    @Throws(SQLException::class)
    override fun cancel() {
        statement.cancel()
    }

    @Throws(SQLException::class)
    override fun getWarnings(): SQLWarning? {
        return statement.getWarnings()
    }

    @Throws(SQLException::class)
    override fun clearWarnings() {
        statement.clearWarnings()
    }

    @Throws(SQLException::class)
    override fun setCursorName(s: String?) {
        statement.setCursorName(s)
    }

    @Throws(SQLException::class)
    override fun getResultSet(): ResultSet? {
        return statement.getResultSet()
    }

    @Throws(SQLException::class)
    override fun getUpdateCount(): Int {
        return statement.getUpdateCount()
    }

    @Throws(SQLException::class)
    override fun getMoreResults(): Boolean {
        return statement.getMoreResults()
    }

    @Throws(SQLException::class)
    override fun setFetchDirection(i: Int) {
        statement.setFetchDirection(i)
    }

    @Throws(SQLException::class)
    override fun getFetchDirection(): Int {
        return statement.getFetchDirection()
    }

    @Throws(SQLException::class)
    override fun setFetchSize(i: Int) {
        statement.setFetchSize(i)
    }

    @Throws(SQLException::class)
    override fun getFetchSize(): Int {
        return statement.getFetchSize()
    }

    @Throws(SQLException::class)
    override fun getResultSetConcurrency(): Int {
        return statement.getResultSetConcurrency()
    }

    @Throws(SQLException::class)
    override fun getResultSetType(): Int {
        return statement.getResultSetType()
    }

    @Throws(SQLException::class)
    override fun addBatch(s: String?) {
        statement.addBatch(s)
    }

    @Throws(SQLException::class)
    override fun clearBatch() {
        statement.clearBatch()
    }

    @Throws(SQLException::class)
    override fun executeBatch(): IntArray? {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun getConnection(): Connection? {
        return statement.getConnection()
    }

    @Throws(SQLException::class)
    override fun getMoreResults(i: Int): Boolean {
        return statement.getMoreResults(i)
    }

    @Throws(SQLException::class)
    override fun getGeneratedKeys(): ResultSet? {
        return statement.getGeneratedKeys()
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?, i: Int): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?, ints: IntArray?): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?, strings: Array<String?>?): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun execute(s: String?, i: Int): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun execute(s: String?, ints: IntArray?): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun execute(s: String?, strings: Array<String?>?): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun getResultSetHoldability(): Int {
        return statement.getResultSetHoldability()
    }

    @Throws(SQLException::class)
    override fun isClosed(): Boolean {
        return statement.isClosed()
    }

    @Throws(SQLException::class)
    override fun setPoolable(b: Boolean) {
        statement.setPoolable(b)
    }

    @Throws(SQLException::class)
    override fun isPoolable(): Boolean {
        return statement.isPoolable()
    }

    @Throws(SQLException::class)
    override fun <T> unwrap(aClass: Class<T?>?): T? {
        return statement.unwrap<T?>(aClass)
    }

    @Throws(SQLException::class)
    override fun isWrapperFor(aClass: Class<*>?): Boolean {
        return statement.isWrapperFor(aClass)
    }

    // JVM-only: java.sql.Statement on desktop/JDK declares closeOnCompletion()/isCloseOnCompletion()
    // as abstract, but Android's java.sql.Statement does not. The markers stay inert
    // comments for the Android build; the desktop engine-jvm build generates active overrides by
    // stripping the marker prefix (see obv_engine/engine-jvm/build.gradle). Do not remove the prefix.
    override fun closeOnCompletion() { statement.closeOnCompletion() }
    override fun isCloseOnCompletion(): Boolean { return statement.isCloseOnCompletion() }
}


internal class DeferrablePreparedStatement(
    private val tag: String?,
    private val statement: PreparedStatement,
    private val session: Session
) : PreparedStatement {
    @Throws(SQLException::class)
    override fun executeQuery(): ResultSet? {
        val startTime = System.nanoTime()
        val res = statement.executeQuery()
        Session.registerQueryTime(tag, (System.nanoTime() - startTime) / 1000)
        return res
    }

    @Throws(SQLException::class)
    override fun executeUpdate(): Int {
        var res: Int
        var startTime: Long
        if (session.autoCommit) {
            try {
                Session.Companion.globalWriteLock.lock()
                startTime = System.nanoTime()
                res = statement.executeUpdate()
            } finally {
                Session.Companion.globalWriteLock.unlock()
            }
        } else {
            startTime = System.nanoTime()
            res = statement.executeUpdate()
        }
        Session.registerQueryTime(tag, (System.nanoTime() - startTime) / 1000)
        return res
    }

    @Throws(SQLException::class)
    override fun execute(): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun close() {
        statement.close()
    }

    @Throws(SQLException::class)
    override fun setNull(i: Int, i1: Int) {
        statement.setNull(i, i1)
    }

    @Throws(SQLException::class)
    override fun setBoolean(i: Int, b: Boolean) {
        statement.setBoolean(i, b)
    }

    @Throws(SQLException::class)
    override fun setByte(i: Int, b: Byte) {
        statement.setByte(i, b)
    }

    @Throws(SQLException::class)
    override fun setShort(i: Int, i1: Short) {
        statement.setShort(i, i1)
    }

    @Throws(SQLException::class)
    override fun setInt(i: Int, i1: Int) {
        statement.setInt(i, i1)
    }

    @Throws(SQLException::class)
    override fun setLong(i: Int, l: Long) {
        statement.setLong(i, l)
    }

    @Throws(SQLException::class)
    override fun setFloat(i: Int, v: Float) {
        statement.setFloat(i, v)
    }

    @Throws(SQLException::class)
    override fun setDouble(i: Int, v: Double) {
        statement.setDouble(i, v)
    }

    @Throws(SQLException::class)
    override fun setBigDecimal(i: Int, bigDecimal: BigDecimal?) {
        statement.setBigDecimal(i, bigDecimal)
    }

    @Throws(SQLException::class)
    override fun setString(i: Int, s: String?) {
        statement.setString(i, s)
    }

    @Throws(SQLException::class)
    override fun setBytes(i: Int, bytes: ByteArray?) {
        statement.setBytes(i, bytes)
    }

    @Throws(SQLException::class)
    override fun setDate(i: Int, date: Date?) {
        statement.setDate(i, date)
    }

    @Throws(SQLException::class)
    override fun setTime(i: Int, time: Time?) {
        statement.setTime(i, time)
    }

    @Throws(SQLException::class)
    override fun setTimestamp(i: Int, timestamp: Timestamp?) {
        statement.setTimestamp(i, timestamp)
    }

    @Throws(SQLException::class)
    override fun setAsciiStream(i: Int, inputStream: InputStream?, i1: Int) {
        statement.setAsciiStream(i, inputStream, i1)
    }

    @Deprecated("")
    @Throws(SQLException::class)
    override fun setUnicodeStream(i: Int, inputStream: InputStream?, i1: Int) {
        statement.setUnicodeStream(i, inputStream, i1)
    }

    @Throws(SQLException::class)
    override fun setBinaryStream(i: Int, inputStream: InputStream?, i1: Int) {
        statement.setBinaryStream(i, inputStream, i1)
    }

    @Throws(SQLException::class)
    override fun clearParameters() {
        statement.clearParameters()
    }

    @Throws(SQLException::class)
    override fun setObject(i: Int, o: Any?, i1: Int) {
        statement.setObject(i, o, i1)
    }

    @Throws(SQLException::class)
    override fun setObject(i: Int, o: Any?) {
        statement.setObject(i, o)
    }

    @Throws(SQLException::class)
    override fun addBatch() {
        statement.addBatch()
    }

    @Throws(SQLException::class)
    override fun setCharacterStream(i: Int, reader: Reader?, i1: Int) {
        statement.setCharacterStream(i, reader, i1)
    }

    @Throws(SQLException::class)
    override fun setRef(i: Int, ref: Ref?) {
        statement.setRef(i, ref)
    }

    @Throws(SQLException::class)
    override fun setBlob(i: Int, blob: Blob?) {
        statement.setBlob(i, blob)
    }

    @Throws(SQLException::class)
    override fun setClob(i: Int, clob: Clob?) {
        statement.setClob(i, clob)
    }

    @Throws(SQLException::class)
    override fun setArray(i: Int, array: SqlArray?) {
        statement.setArray(i, array)
    }

    @Throws(SQLException::class)
    override fun getMetaData(): ResultSetMetaData? {
        return statement.getMetaData()
    }

    @Throws(SQLException::class)
    override fun setDate(i: Int, date: Date?, calendar: Calendar?) {
        statement.setDate(i, date, calendar)
    }

    @Throws(SQLException::class)
    override fun setTime(i: Int, time: Time?, calendar: Calendar?) {
        statement.setTime(i, time, calendar)
    }

    @Throws(SQLException::class)
    override fun setTimestamp(i: Int, timestamp: Timestamp?, calendar: Calendar?) {
        statement.setTimestamp(i, timestamp, calendar)
    }

    @Throws(SQLException::class)
    override fun setNull(i: Int, i1: Int, s: String?) {
        statement.setNull(i, i1, s)
    }

    @Throws(SQLException::class)
    override fun setURL(i: Int, url: URL?) {
        statement.setURL(i, url)
    }

    @Throws(SQLException::class)
    override fun getParameterMetaData(): ParameterMetaData? {
        return statement.getParameterMetaData()
    }

    @Throws(SQLException::class)
    override fun setRowId(i: Int, rowId: RowId?) {
        statement.setRowId(i, rowId)
    }

    @Throws(SQLException::class)
    override fun setNString(i: Int, s: String?) {
        statement.setNString(i, s)
    }

    @Throws(SQLException::class)
    override fun setNCharacterStream(i: Int, reader: Reader?, l: Long) {
        statement.setNCharacterStream(i, reader, l)
    }

    @Throws(SQLException::class)
    override fun setNClob(i: Int, nClob: NClob?) {
        statement.setNClob(i, nClob)
    }

    @Throws(SQLException::class)
    override fun setClob(i: Int, reader: Reader?, l: Long) {
        statement.setClob(i, reader, l)
    }

    @Throws(SQLException::class)
    override fun setBlob(i: Int, inputStream: InputStream?, l: Long) {
        statement.setBlob(i, inputStream, l)
    }

    @Throws(SQLException::class)
    override fun setNClob(i: Int, reader: Reader?, l: Long) {
        statement.setNClob(i, reader, l)
    }

    @Throws(SQLException::class)
    override fun setSQLXML(i: Int, sqlxml: SQLXML?) {
        statement.setSQLXML(i, sqlxml)
    }

    @Throws(SQLException::class)
    override fun setObject(i: Int, o: Any?, i1: Int, i2: Int) {
        statement.setObject(i, o, i1, i2)
    }

    @Throws(SQLException::class)
    override fun setAsciiStream(i: Int, inputStream: InputStream?, l: Long) {
        statement.setAsciiStream(i, inputStream, l)
    }

    @Throws(SQLException::class)
    override fun setBinaryStream(i: Int, inputStream: InputStream?, l: Long) {
        statement.setBinaryStream(i, inputStream, l)
    }

    @Throws(SQLException::class)
    override fun setCharacterStream(i: Int, reader: Reader?, l: Long) {
        statement.setCharacterStream(i, reader, l)
    }

    @Throws(SQLException::class)
    override fun setAsciiStream(i: Int, inputStream: InputStream?) {
        statement.setAsciiStream(i, inputStream)
    }

    @Throws(SQLException::class)
    override fun setBinaryStream(i: Int, inputStream: InputStream?) {
        statement.setBinaryStream(i, inputStream)
    }

    @Throws(SQLException::class)
    override fun setCharacterStream(i: Int, reader: Reader?) {
        statement.setCharacterStream(i, reader)
    }

    @Throws(SQLException::class)
    override fun setNCharacterStream(i: Int, reader: Reader?) {
        statement.setNCharacterStream(i, reader)
    }

    @Throws(SQLException::class)
    override fun setClob(i: Int, reader: Reader?) {
        statement.setClob(i, reader)
    }

    @Throws(SQLException::class)
    override fun setBlob(i: Int, inputStream: InputStream?) {
        statement.setBlob(i, inputStream)
    }

    @Throws(SQLException::class)
    override fun setNClob(i: Int, reader: Reader?) {
        statement.setNClob(i, reader)
    }

    @Throws(SQLException::class)
    override fun executeQuery(s: String?): ResultSet? {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun getMaxFieldSize(): Int {
        return statement.getMaxFieldSize()
    }

    @Throws(SQLException::class)
    override fun setMaxFieldSize(i: Int) {
        statement.setMaxFieldSize(i)
    }

    @Throws(SQLException::class)
    override fun getMaxRows(): Int {
        return statement.getMaxRows()
    }

    @Throws(SQLException::class)
    override fun setMaxRows(i: Int) {
        statement.setMaxRows(i)
    }

    @Throws(SQLException::class)
    override fun setEscapeProcessing(b: Boolean) {
        statement.setEscapeProcessing(b)
    }

    @Throws(SQLException::class)
    override fun getQueryTimeout(): Int {
        return statement.getQueryTimeout()
    }

    @Throws(SQLException::class)
    override fun setQueryTimeout(i: Int) {
        statement.setQueryTimeout(i)
    }

    @Throws(SQLException::class)
    override fun cancel() {
        statement.cancel()
    }

    @Throws(SQLException::class)
    override fun getWarnings(): SQLWarning? {
        return statement.getWarnings()
    }

    @Throws(SQLException::class)
    override fun clearWarnings() {
        statement.clearWarnings()
    }

    @Throws(SQLException::class)
    override fun setCursorName(s: String?) {
        statement.setCursorName(s)
    }

    @Throws(SQLException::class)
    override fun execute(s: String?): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun getResultSet(): ResultSet? {
        return statement.getResultSet()
    }

    @Throws(SQLException::class)
    override fun getUpdateCount(): Int {
        return statement.getUpdateCount()
    }

    @Throws(SQLException::class)
    override fun getMoreResults(): Boolean {
        return statement.getMoreResults()
    }

    @Throws(SQLException::class)
    override fun setFetchDirection(i: Int) {
        statement.setFetchDirection(i)
    }

    @Throws(SQLException::class)
    override fun getFetchDirection(): Int {
        return statement.getFetchDirection()
    }

    @Throws(SQLException::class)
    override fun setFetchSize(i: Int) {
        statement.setFetchSize(i)
    }

    @Throws(SQLException::class)
    override fun getFetchSize(): Int {
        return statement.getFetchSize()
    }

    @Throws(SQLException::class)
    override fun getResultSetConcurrency(): Int {
        return statement.getResultSetConcurrency()
    }

    @Throws(SQLException::class)
    override fun getResultSetType(): Int {
        return statement.getResultSetType()
    }

    @Throws(SQLException::class)
    override fun addBatch(s: String?) {
        statement.addBatch(s)
    }

    @Throws(SQLException::class)
    override fun clearBatch() {
        statement.clearBatch()
    }

    @Throws(SQLException::class)
    override fun executeBatch(): IntArray? {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun getConnection(): Connection? {
        return statement.getConnection()
    }

    @Throws(SQLException::class)
    override fun getMoreResults(i: Int): Boolean {
        return statement.getMoreResults(i)
    }

    @Throws(SQLException::class)
    override fun getGeneratedKeys(): ResultSet? {
        return statement.getGeneratedKeys()
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?, i: Int): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?, ints: IntArray?): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun executeUpdate(s: String?, strings: kotlin.Array<String?>?): Int {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun execute(s: String?, i: Int): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun execute(s: String?, ints: IntArray?): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun execute(s: String?, strings: kotlin.Array<String?>?): Boolean {
        throw SQLException("Not implemented")
    }

    @Throws(SQLException::class)
    override fun getResultSetHoldability(): Int {
        return statement.getResultSetHoldability()
    }

    @Throws(SQLException::class)
    override fun isClosed(): Boolean {
        return statement.isClosed()
    }

    @Throws(SQLException::class)
    override fun setPoolable(b: Boolean) {
        statement.setPoolable(b)
    }

    @Throws(SQLException::class)
    override fun isPoolable(): Boolean {
        return statement.isPoolable()
    }

    @Throws(SQLException::class)
    override fun <T> unwrap(aClass: Class<T?>?): T? {
        return statement.unwrap<T?>(aClass)
    }

    @Throws(SQLException::class)
    override fun isWrapperFor(aClass: Class<*>?): Boolean {
        return statement.isWrapperFor(aClass)
    }

    // JVM-only: java.sql.Statement on desktop/JDK declares closeOnCompletion()/isCloseOnCompletion()
    // as abstract, but Android's java.sql.Statement does not. The markers stay inert
    // comments for the Android build; the desktop engine-jvm build generates active overrides by
    // stripping the marker prefix (see obv_engine/engine-jvm/build.gradle). Do not remove the prefix.
    override fun closeOnCompletion() { statement.closeOnCompletion() }
    override fun isCloseOnCompletion(): Boolean { return statement.isCloseOnCompletion() }
}