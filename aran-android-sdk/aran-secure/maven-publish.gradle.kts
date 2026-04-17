afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = "org.mazhai.aran"
                artifactId = "aran-secure"
                version = project.findProperty("VERSION_NAME")?.toString() ?: "1.0.0"

                pom {
                    name.set("Aran Secure")
                    description.set("Enterprise Fintech RASP SDK — drop-in security layer for Android.")
                    url.set("https://aran.mazhai.org")

                    licenses {
                        license {
                            name.set("Proprietary")
                            url.set("https://aran.mazhai.org/license")
                        }
                    }

                    developers {
                        developer {
                            id.set("mazhai")
                            name.set("Mazhai Engineering")
                            email.set("sdk@mazhai.org")
                        }
                    }
                }
            }
        }

        repositories {
            maven {
                name = "MazhaiPrivate"
                url = uri(
                    project.findProperty("MAVEN_REPO_URL")?.toString()
                        ?: "${rootProject.layout.buildDirectory.get()}/repo"
                )
                credentials {
                    username = project.findProperty("MAVEN_USERNAME")?.toString() ?: ""
                    password = project.findProperty("MAVEN_PASSWORD")?.toString() ?: ""
                }
            }
        }
    }
}
