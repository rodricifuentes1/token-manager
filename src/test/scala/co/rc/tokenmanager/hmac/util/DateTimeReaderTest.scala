package co.rc.tokenmanager.hmac.util

import com.typesafe.config.ConfigException.{ WrongType, BadValue }
import com.typesafe.config.{ Config, ConfigFactory }
import net.ceedubs.ficus.Ficus._
import org.joda.time.DateTime
import org.specs2.mutable.Specification

/**
 * Test specification for DateTimeReader
 */
class DateTimeReaderTest extends Specification {
  sequential

  import DateTimeReader.reader

  "DateTimeReader" should {

    "READ: Read number value to ReadableInstant (DateTime)" in {

      // Config for this test
      val config: Config = ConfigFactory.parseString(
        """
          |num = 123
        """.stripMargin )

      config.as[ DateTime ]( "num" ) must_== new DateTime( 123L )
    }

    "READ: Read iso-8601 string value to ReadableInstant (DateTime)" in {

      // Config for this test
      val config: Config = ConfigFactory.parseString(
        """
          |str = "2013-01-05T12:00:00Z"
        """.stripMargin )

      config.as[ DateTime ]( "str" ) must_== new DateTime( "2013-01-05T12:00:00Z" )
    }

    "READ: Throw an exception reading an invalid DateTime value" in {

      // Config for this test
      val config: Config = ConfigFactory.parseString(
        """
          |invalid = "invalid"
        """.stripMargin )

      config.as[ DateTime ]( "invalid" ) must throwA[ BadValue ]
    }

    "READ: Throw an exception reading an unsupported config type value" in {

      // Config for this test
      val config: Config = ConfigFactory.parseString(
        """
          |unsupported = [ "2013-01-05T12:00:00Z", "2014-01-05T12:00:00Z" ]
        """.stripMargin )

      config.as[ DateTime ]( "unsupported" ) must throwA[ WrongType ]
    }

  }

}
