plugins {
    kotlin("jvm") version "2.4.10"
    id("com.gradleup.shadow") version "9.6.1"
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
    // MUST be compileOnly -- shading org.keycloak.* classes into the provider JAR file
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
 * The distributed artifact: one JAR file to drop in /opt/keycloak/providers.
 *
 * kotlin-stdlib is the only runtime dependency Keycloak does not already ship, and it is
 * relocated rather than shipped beside us. Keycloak uses a single unrestricted
 * classloader and gives providers/ precedence over its own libraries, so a bare stdlib
 * JAR file there is global -- another Kotlin provider at a different version and one of them
 * silently wins.
 *
 * Kotlin is relocated and nothing else. Shading org.keycloak is what produces
 * "ServiceConfigurationError: <Spi> not a subtype" at startup; Keycloak and Apache
 * HttpClient are compileOnly and must stay out of the JAR file entirely.
 */
tasks.shadowJar {
    archiveClassifier = ""
    relocate("kotlin", "com.nitrokey.nethsm.keycloak.shaded.kotlin")
    relocate("org.jetbrains.annotations", "com.nitrokey.nethsm.keycloak.shaded.annotations")
    // Kotlin's module metadata refers to the original package names and is only used by
    // the Kotlin compiler, which never consumes this JAR file.
    exclude("META-INF/*.kotlin_module")
    exclude("META-INF/maven/**")
    mergeServiceFiles()
}

// The plain JAR file would collide with the shaded one now that it has no classifier, and
// nothing consumes it.
tasks.jar { enabled = false }

/**
 * Stages exactly what a user deploys, so the testbed and CI exercise the released
 * artifact rather than a differently-assembled one.
 */
val collectRuntimeJars = tasks.register<Sync>("collectRuntimeJars") {
    description = "Stages the shaded provider JAR file for /opt/keycloak/providers"
    group = "distribution"
    from(tasks.shadowJar)
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
