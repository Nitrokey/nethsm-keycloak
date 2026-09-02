plugins {
    kotlin("jvm") version "2.4.10"
}

val keycloakVersion = project.property("keycloakVersion") as String

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // Treat Keycloak's unannotated Java types as platform types (the default),
        // but keep our own code strict.
        allWarningsAsErrors = true
    }
}

dependencies {
    // Keycloak is on the server classpath at runtime. Everything Keycloak ships
    // MUST be compileOnly -- shading org.keycloak.* classes into the provider jar
    // is what produces "ServiceConfigurationError: <Spi> not a subtype" at startup.
    compileOnly("org.keycloak:keycloak-server-spi:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-services:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-core:$keycloakVersion")

    // Shipped by Keycloak in lib/lib/main (4.5.14 in 26.7.x). Used instead of
    // java.net.http because that client forces hostname verification regardless of the
    // SSLParameters it is given, which rules out pinning a self-signed NetHSM cert.
    compileOnly("org.apache.httpcomponents:httpclient:4.5.14")

    testImplementation(kotlin("test"))
    testImplementation("org.keycloak:keycloak-server-spi:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-services:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-core:$keycloakVersion")
}

tasks.test {
    useJUnitPlatform()
}

/**
 * kotlin-stdlib is the extension's only runtime dependency that Keycloak does not
 * already ship. Keycloak uses a single unrestricted classloader and gives
 * providers/ precedence over built-in libraries, so a bare stdlib jar dropped in
 * providers/ becomes global. That is fine when you own the whole image (what
 * docker/ does) and a hazard when shipping to third parties who may deploy another
 * Kotlin provider at a different version.
 *
 * `collectRuntimeJars` produces the deployable set for the own-the-image case.
 * For third-party distribution, add com.gradleup.shadow and relocate `kotlin.**`
 * -- and nothing else.
 */
val collectRuntimeJars = tasks.register<Sync>("collectRuntimeJars") {
    description = "Stages the provider jar + kotlin-stdlib for /opt/keycloak/providers"
    group = "distribution"
    from(tasks.jar)
    from(configurations.runtimeClasspath)
    into(layout.buildDirectory.dir("providers"))
}

tasks.build {
    dependsOn(collectRuntimeJars)
}
