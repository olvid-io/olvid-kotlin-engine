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

import java.io.FileInputStream
import java.util.Properties

plugins {
    kotlin("jvm") version "2.4.0"
    `java-library`
    `maven-publish`
    signing
}

group = "io.olvid.messenger"
version = "1.2.0"

repositories {
    mavenCentral()
}

sourceSets {
    named("main") {
        java.setSrcDirs(listOf("src/main/java"))
        resources.setSrcDirs(listOf("src/main/resources"))
    }
    named("test") {
        java.setSrcDirs(listOf("src/test/java"))
        resources.setSrcDirs(listOf("src/test/resources"))
    }
}
kotlin {
    sourceSets {
        named("main") { kotlin.setSrcDirs(listOf("src/main/java")) }
        named("test") { kotlin.setSrcDirs(listOf("src/test/java")) }
    }
    jvmToolchain(17)
}

dependencies {
    // do not update further: jackson >2.13 does not work on older Android APIs (the Android app is a consumer)
    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.4")

    implementation("org.slf4j:slf4j-api:2.0.17")
    implementation("org.slf4j:slf4j-simple:2.0.17")

    implementation("org.bitbucket.b_c:jose4j:0.9.6")

    implementation("com.squareup.okhttp3:okhttp:5.3.2")
    implementation("net.iharder:base64:2.3.9")

    // The engine talks only java.sql and discovers the driver via DriverManager/ServiceLoader at
    // runtime, so it binds no SQLite/SQLCipher driver — each consumer (Android app, desktop client,
    // bots) provides its own. The engine's own JVM unit tests use a host-native driver.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.xerial:sqlite-jdbc:3.50.3.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

val cred = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    cred.load(FileInputStream(localPropertiesFile))
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["java"])

                groupId = "io.olvid.messenger"
                artifactId = "olvid-kotlin-engine"

                pom {
                    name.set("Olvid Kotlin Engine")
                    description.set("The Olvid engine used in the Android and Windows/Linux versions of Olvid")
                    url.set("https://github.com/olvid-io/olvid-kotlin-engine")

                    scm {
                        url.set("https://github.com/olvid-io/olvid-kotlin-engine")
                    }

                    licenses {
                        license {
                            name.set("The GNU Affero General Public License, Version 3.0")
                            url.set("LICENSE")
                        }
                    }

                    developers {
                        developer {
                            id.set("finiasz")
                            name.set("Matthieu Finiasz")
                            email.set("opensource@olvid.io")
                        }
                    }
                }
            }
        }

        repositories {
            maven {
                name = "ossrh-staging-api"
                url = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
                credentials {
                    // Load values from local.properties
                    username = cred.getProperty("maven.username")
                    password = cred.getProperty("maven.password")
                }
            }
        }
    }

    signing {
        // Load values from local.properties
        val signingKeyId = cred.getProperty("signing.key_id")
        val signingKey = cred.getProperty("signing.key")
        val signingPassword = cred.getProperty("signing.password")

        useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)

        sign(publishing.publications["release"])
    }
}
