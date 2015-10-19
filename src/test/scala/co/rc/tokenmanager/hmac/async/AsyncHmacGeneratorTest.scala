package co.rc.tokenmanager.hmac.async

import co.rc.tokenmanager.hmac.base.TimeDuration
import co.rc.tokenmanager.util.Converters._
import co.rc.tokenmanager.util.TokenException

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet
import com.typesafe.config.ConfigFactory

import java.text.ParseException

import org.joda.time.DateTime
import org.specs2.mutable.Specification

import scala.concurrent.duration._
import scala.concurrent.{ Future, Await, ExecutionContext }
import scala.concurrent.ExecutionContext.Implicits

/**
 * Test specification for AsyncHmacGenerator
 * Max await block for each future is: 5 seconds
 */
class AsyncHmacGeneratorTest extends Specification {
  sequential

  "AsyncHmacGenerator" should {

    // ----------------------------------
    // CONFIG
    // ----------------------------------

    "GENERATE: Get an exception when config algorithm is invalid" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "somealgo"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future exception
      val futureException: Future[ Throwable ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      ).failed

      // Exception
      val ex: Throwable = Await.result( futureException, 5.seconds )

      ex must beAnInstanceOf[ IllegalArgumentException ]
      ex.getMessage must_== "requirement failed: Invalid algorithm for HMAC generator"

    }

    "GENERATE: Get an exception when config default expiration time is invalid" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "invalid-unit"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future exception
      val futureException: Future[ Throwable ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      ).failed

      // Exception
      val ex: Throwable = Await.result( futureException, 5.seconds )

      ex must beAnInstanceOf[ IllegalArgumentException ]
      ex.getMessage must_== "requirement failed: Invalid unit for time duration"
    }

    // ----------------------------------
    // CONFIG DATA
    // ----------------------------------

    "GENERATE: Generate HMAC token with config data" in {

      // Java-Scala conversions
      import scala.collection.JavaConversions._

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |    data {
          |     issuer = "test-issuer"
          |     subject = "test-subject"
          |     audience = ["aud1", "aud2"]
          |     expirationTime {
          |       unit = "minutes"
          |       length = 6
          |     }
          |     notBefore = "2015-11-01T12:00:00Z"
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ ReadOnlyJWTClaimsSet ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        claims <- AsyncHmacGenerator.getJWTClaims( token, conf = config )
      } yield {
        claims
      }

      // Boolean result
      val result: ReadOnlyJWTClaimsSet = Await.result( future, 5.seconds )

      result.getIssuer must_== "test-issuer"
      result.getSubject must_== "test-subject"
      result.getAudience.toList must_== List( "aud1", "aud2" )
      new DateTime( result.getNotBeforeTime.getTime ).getMillis must_== new DateTime( "2015-11-01T12:00:00Z" ).getMillis
    }

    // ----------------------------------
    // EXPIRATION TIME
    // ----------------------------------

    "GENERATE: Generate 10 seconds expiration time HMAC token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" ),
        expirationTime = Some( TimeDuration( "seconds", 10 ) )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    "GENERATE: Generate 10 hours expiration time HMAC token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "hours"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    "GENERATE: Generate 10 days expiration time HMAC token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "days"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    "GENERATE: Generate 10 weeks expiration time HMAC token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "weeks"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" ),
        notBefore = Some( new DateTime().plusDays( 1 ) )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    // ----------------------------------
    // HS-256
    // ----------------------------------

    "GENERATE: Get an exception when trying to generate HS-256 HMAC token with invalid secret" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = ""
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future exception
      val futureException: Future[ Throwable ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      ).failed

      // Exception
      val ex: Throwable = Await.result( futureException, 5.seconds )

      ex must beAnInstanceOf[ IllegalArgumentException ]
      ex.getMessage must_== "requirement failed: Invalid secret length for HS256 algorithm"

    }

    "GENERATE: Generate HS-256 HMAC token successfully" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    "GENERATE: Generate HS-256 HMAC token with all options successfully" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" ),
        "1",
        Some( "RC INC " ),
        Some( "subject" ),
        Some( List( "aud1, aud2" ) ),
        Some( TimeDuration( "minutes", 10 ) ),
        Some( new DateTime().plusDays( 2 ) )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    // ----------------------------------
    // HS-384
    // ----------------------------------

    "GENERATE: Get an exception when trying to generate HS-384 HMAC token with invalid secret" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS384"
          |    secret = ""
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future exception
      val futureException: Future[ Throwable ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      ).failed

      // Exception
      val ex: Throwable = Await.result( futureException, 5.seconds )

      ex must beAnInstanceOf[ IllegalArgumentException ]
      ex.getMessage must_== "requirement failed: Invalid secret length for HS384 algorithm"

    }

    "GENERATE: Generate HS-384 HMAC token successfully" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS384"
          |    secret = "gIKDh0Ta2MiFi7NjULXntD2QZbREOSjCUEffNzRiSFooGXNL"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    "GENERATE: Generate HS-384 HMAC token with all options successfully" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS384"
          |    secret = "gIKDh0Ta2MiFi7NjULXntD2QZbREOSjCUEffNzRiSFooGXNL"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" ),
        "1",
        Some( "RC INC " ),
        Some( "subject" ),
        Some( List( "aud1, aud2" ) ),
        Some( TimeDuration( "minutes", 10 ) ),
        Some( new DateTime().plusDays( 2 ) )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    // ----------------------------------
    // HS-512
    // ----------------------------------

    "GENERATE: Get an exception when trying to generate HS-512 HMAC token with invalid secret" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS512"
          |    secret = ""
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future exception
      val futureException: Future[ Throwable ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      ).failed

      // Exception
      val ex: Throwable = Await.result( futureException, 5.seconds )

      ex must beAnInstanceOf[ IllegalArgumentException ]
      ex.getMessage must_== "requirement failed: Invalid secret length for HS512 algorithm"

    }

    "GENERATE: Generate HS-512 HMAC token successfully" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS512"
          |    secret = "o5ejtcyqTRKMYkhn7KLS6xAU0p4q5OqMnD4gkvzGXN90LQUnrwJQDvRCtb2kP8wg"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    "GENERATE: Generate HS-512 HMAC token with all options successfully" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS512"
          |    secret = "o5ejtcyqTRKMYkhn7KLS6xAU0p4q5OqMnD4gkvzGXN90LQUnrwJQDvRCtb2kP8wg"
          |    default-expiration-time {
          |       unit = "minutes"
          |       length = 30
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Future token
      val generationFuture: Future[ String ] = generator.generateToken(
        Map( "id" ~> 1, "gender" ~> "Male" ),
        "1",
        Some( "RC INC " ),
        Some( "subject" ),
        Some( List( "aud1, aud2" ) ),
        Some( TimeDuration( "minutes", 10 ) ),
        Some( new DateTime().plusDays( 2 ) )
      )

      // Generated token
      val token: String = Await.result( generationFuture, 5.seconds )

      token must beAnInstanceOf[ String ]
      token.split( "\\." ).size must_== 3

    }

    // ----------------------------------
    // TOKEN VALIDATION STRUCTURE CHECK
    // ----------------------------------

    "VALIDATE: Throws a ParseException when validating an empty token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Validation future
      val validationException = AsyncHmacGenerator.validateToken( "", conf = config ).failed

      // Validation exception
      val ex: Throwable = Await.result( validationException, 5.seconds )

      ex must beAnInstanceOf[ ParseException ]
      ex.getMessage must_== "Invalid serialized plain/JWS/JWE object: Missing part delimiters"

    }

    "VALIDATE: Throws a ParseException when validating a malformed token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Validation future
      val validationException = AsyncHmacGenerator.validateToken( "invalid-token", conf = config ).failed

      // Validation exception
      val ex: Throwable = Await.result( validationException, 5.seconds )

      ex must beAnInstanceOf[ ParseException ]
      ex.getMessage must_== "Invalid serialized plain/JWS/JWE object: Missing part delimiters"

    }

    // ----------------------------------
    // TOKEN VALIDATION SIGNATURE CHECK
    // ----------------------------------

    "VALIDATE: Get false when validating a well formed but unsigned token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Validation future
      val validationFuture = AsyncHmacGenerator.validateToken( "eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA", conf = config )

      // Validation exception
      val result: Boolean = Await.result( validationFuture, 5.seconds )

      result must_== false

    }

    "VALIDATE: Get true when validating a well formed token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ Boolean ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        validation <- AsyncHmacGenerator.validateToken( token, validateExpirationTime = false, validateNotBeforeDate = false, conf = config )
      } yield {
        validation
      }

      // Boolean result
      val result: Boolean = Await.result( future, 5.seconds )

      result must_== true

    }

    // ----------------------------------
    // TOKEN VALIDATION PARAMS CHECK
    // ----------------------------------

    "VALIDATE: Get true when validating a well formed token with expiration-time flag" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ Boolean ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        validation <- AsyncHmacGenerator.validateToken( token, validateExpirationTime = true, validateNotBeforeDate = false, conf = config )
      } yield {
        validation
      }

      // Boolean result
      val result: Boolean = Await.result( future, 5.seconds )

      result must_== true

    }

    "VALIDATE: Get an exception when validating a well formed token with not-before flag when is not defined " in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ Throwable ] = ( for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        validation <- AsyncHmacGenerator.validateToken( token, validateExpirationTime = false, validateNotBeforeDate = true, conf = config )
      } yield {
        validation
      } ).failed

      // Boolean result
      val ex: Throwable = Await.result( future, 5.seconds )

      ex must beAnInstanceOf[ TokenException ]
      ex.getMessage must_== "Not before time is not defined"
    }

    "VALIDATE: Get true when validating a well formed token with not-before " in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ Boolean ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ), notBefore = Some( new DateTime() ) )
        validation <- AsyncHmacGenerator.validateToken( token, validateExpirationTime = false, validateNotBeforeDate = true, conf = config )
      } yield {
        validation
      }

      // Boolean result
      val result: Boolean = Await.result( future, 5.seconds )

      result must_== true
    }

    // ----------------------------------
    // JWT CLAIMSSET
    // ----------------------------------

    "CLAIMS: Get an exception trying to get claims from an invalid token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generation and validation future
      val future: Future[ Throwable ] = AsyncHmacGenerator.getJWTClaims( "", conf = config ).failed

      // Boolean result
      val ex: Throwable = Await.result( future, 5.seconds )

      ex must beAnInstanceOf[ ParseException ]
      ex.getMessage must_== "Invalid serialized plain/JWS/JWE object: Missing part delimiters"
    }

    "CLAIMS: Get jwt claims from a well formed token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ ReadOnlyJWTClaimsSet ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        claims <- AsyncHmacGenerator.getJWTClaims( token, conf = config )
      } yield {
        claims
      }

      // Boolean result
      val result: ReadOnlyJWTClaimsSet = Await.result( future, 5.seconds )

      result.getCustomClaim( "id" ) must_== 1
      result.getCustomClaim( "gender" ) must_== "Male"
    }

    "CLAIMS: Get an exception trying to get specified claim from an invalid token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generation and validation future
      val future: Future[ Throwable ] = AsyncHmacGenerator.getJwtClaim( "", "specific-claim", conf = config ).failed

      // Boolean result
      val ex: Throwable = Await.result( future, 5.seconds )

      ex must beAnInstanceOf[ ParseException ]
      ex.getMessage must_== "Invalid serialized plain/JWS/JWE object: Missing part delimiters"
    }

    "CLAIMS: Get a None when trying to find a non-existent claim" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ Option[ AnyRef ] ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        claim <- AsyncHmacGenerator.getJwtClaim( token, "claim1", conf = config )
      } yield {
        claim
      }

      // Boolean result
      val result: Option[ AnyRef ] = Await.result( future, 5.seconds )

      result.isDefined must_== false

    }

    "CLAIMS: Find some existent claims in a valid token" in {

      // Execution context for future management
      implicit val executionContext: ExecutionContext = Implicits.global

      // Config for this test
      val config = ConfigFactory.parseString(
        """
          |co.rc.tokenmanager {
          |  hmac {
          |    algorithm = "HS256"
          |    secret = "GppEgpOvbqNdrTY5kwxMB3xAphJIXZdZ"
          |    default-expiration-time {
          |       unit = "seconds"
          |       length = 10
          |    }
          |  }
          |}
        """.stripMargin )

      // Generator instance
      val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )

      // Generation and validation future
      val future: Future[ ( Option[ AnyRef ], Option[ AnyRef ] ) ] = for {
        token <- generator.generateToken( Map( "id" ~> 1, "gender" ~> "Male" ) )
        claim1 <- AsyncHmacGenerator.getJwtClaim( token, "id", conf = config )
        claim2 <- AsyncHmacGenerator.getJwtClaim( token, "gender", conf = config )
      } yield {
        ( claim1, claim2 )
      }

      // Boolean result
      val result: ( Option[ AnyRef ], Option[ AnyRef ] ) = Await.result( future, 5.seconds )

      result._1.isDefined must_== true
      result._1.get must_== 1

      result._2.isDefined must_== true
      result._2.get must_== "Male"

    }

  }

}
