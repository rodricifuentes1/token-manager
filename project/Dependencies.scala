import sbt._

object Dependencies {

  /**
  * Defines repository resolvers
  */
  val resolvers = Seq(
    "Scalaz releases" at "http://dl.bintray.com/scalaz/releases",
    "Sonatype releases" at "http://oss.sonatype.org/content/repositories/releases",
    "Sonatype snapshots" at "http://oss.sonatype.org/content/repositories/snapshots",
    "Typesafe releases" at "http://repo.typesafe.com/typesafe/releases/"
  )

  // -----------------------------------
  // VERSIONS
  // -----------------------------------

  // Functional programming
  val scalazVersion: String = "7.1.3"
  
  // Logging
  val logbackVersion: String = "1.1.3"
  val scalaloggingVersion: String = "3.1.0"

  // Utils
  val ficusVersion: String = "1.1.2"
  val nScalaTimeVersion: String = "2.0.0"
  val nimbusVersion: String = "3.9.2"
  
  // Testing
  val specs2Version: String = "3.6.2"
  

  // -----------------------------------
  // DEPENDENCIES
  // -----------------------------------
  val all = Seq(
    "org.scalaz" %% "scalaz-core" % scalazVersion,
    
    "ch.qos.logback" % "logback-classic" % logbackVersion,
    "com.typesafe.scala-logging" %% "scala-logging" % scalaloggingVersion,

    "net.ceedubs" %% "ficus" % ficusVersion,
    "com.github.nscala-time" %% "nscala-time" % nScalaTimeVersion,
    "com.nimbusds" % "nimbus-jose-jwt" % nimbusVersion,

    "org.specs2" %% "specs2-core" % specs2Version % "test"
  )

}
