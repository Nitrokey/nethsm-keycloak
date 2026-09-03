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

/**
 * End-to-end tests. The system under test is Keycloak: they drive its token, JWKS and
 * admin endpoints and assert on what it does. NetHSM is a fixture the compose stack
 * brings up, not the subject -- with one deliberate exception, the contract test that
 * pins the NetHSM PKCS1 behaviour the whole RSA path is built on.
 */
val integrationTestSources = sourceSets.create("integrationTest") {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

// The integration tests need everything the unit tests need, plus the extension itself.
configurations["integrationTestImplementation"].extendsFrom(configurations["testImplementation"])
configurations["integrationTestRuntimeOnly"].extendsFrom(configurations["testRuntimeOnly"])

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

    // ECDSAAlgorithm's DER converters go through CryptoIntegration.getProvider(), which
    // Keycloak initialises at startup. Tests have to stand that up themselves.
    testRuntimeOnly("org.keycloak:keycloak-crypto-default:$keycloakVersion")

    // The contract test drives the extension's own NetHsmClient, so the integration
    // tests need the HTTP client Keycloak would otherwise have provided at runtime.
    add("integrationTestImplementation", "org.apache.httpcomponents:httpclient:4.5.14")
    add("integrationTestImplementation", "org.junit.jupiter:junit-jupiter-params:5.11.4")
    add("integrationTestRuntimeOnly", "org.keycloak:keycloak-crypto-default:$keycloakVersion")
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

val composeUp = tasks.register<Exec>("composeUp") {
    description = "Starts the NetHSM + Keycloak testbed"
    group = "verification"
    dependsOn(collectRuntimeJars)
    workingDir = layout.projectDirectory.dir("docker").asFile
    commandLine("docker", "compose", "up", "-d", "--build")
}

val composeDown = tasks.register<Exec>("composeDown") {
    description = "Tears down the testbed, discarding NetHSM state"
    group = "verification"
    workingDir = layout.projectDirectory.dir("docker").asFile
    commandLine("docker", "compose", "down", "-v")
    isIgnoreExitValue = true
}

/**
 * Deliberately not wired into `check`: every run pays for an image build and
 * `kc.sh build`, so `./gradlew build` stays fast.
 */
tasks.register<Test>("integrationTest") {
    description = "Runs the end-to-end tests against the testbed"
    group = "verification"
    testClassesDirs = integrationTestSources.output.classesDirs
    classpath = integrationTestSources.runtimeClasspath
    useJUnitPlatform()
    // One Keycloak and one NetHSM are shared; isolation comes from a realm per class,
    // and FailClosedIT takes NetHSM away for a moment.
    maxParallelForks = 1

    // Never up-to-date. What these tests exercise lives in containers, which Gradle
    // cannot see, so unchanged sources say nothing about whether they would still pass.
    // Without this, a re-run reports BUILD SUCCESSFUL having executed zero tests.
    outputs.upToDateWhen { false }
    dependsOn(composeUp)
    finalizedBy(composeDown)
    shouldRunAfter(tasks.test)
    testLogging {
        events("passed", "failed", "skipped")
    }
}
