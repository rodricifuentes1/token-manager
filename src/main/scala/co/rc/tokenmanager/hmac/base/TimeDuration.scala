package co.rc.tokenmanager.hmac.base

import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ValueReader

/**
 * Utility class that defines finite time duration
 * @param unit Time unit
 * @param length Time length value
 */
case class TimeDuration( unit: String, length: Int ) {
  require( List(
    "s", "second", "seconds",
    "m", "minute", "minutes",
    "h", "hour", "hours",
    "d", "day", "days",
    "w", "week", "weeks" ).contains( unit ), "Invalid unit for time duration" )
}

object TimeDuration {

  // Implicit value reader for ficus config
  implicit val reader: ValueReader[ TimeDuration ] = ValueReader.relative { config =>
    TimeDuration(
      config.as[ String ]( "unit" ),
      config.as[ Int ]( "length" )
    )
  }

}
