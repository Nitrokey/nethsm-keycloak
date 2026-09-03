package com.nitrokey.nethsm.keycloak.support

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Controls individual services of the testbed, so a test can take NetHSM away and put it
 * back. Gradle's `composeUp`/`composeDown` own the stack's lifecycle; this is only for
 * mid-test manipulation.
 */
object Compose {

    private val workingDir = File(System.getProperty("user.dir"), "docker")

    fun stop(service: String) = run("stop", service)

    fun start(service: String) = run("start", service)

    private fun run(vararg args: String) {
        val command = listOf("docker", "compose", *args)
        // Output goes to a file rather than a pipe: reading a pipe to EOF before
        // waitFor() deadlocks if the command hangs, and the timeout below would never
        // be reached.
        val log = File.createTempFile("compose", ".log").apply { deleteOnExit() }
        val process = ProcessBuilder(command)
            .directory(workingDir)
            .redirectErrorStream(true)
            .redirectOutput(log)
            .start()

        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            error("timed out after 60s: ${command.joinToString(" ")}\n${log.readText()}")
        }
        check(process.exitValue() == 0) { "${command.joinToString(" ")} failed:\n${log.readText()}" }
    }
}
