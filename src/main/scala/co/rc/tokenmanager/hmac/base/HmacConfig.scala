package co.rc.tokenmanager.hmac.base

import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ValueReader

/**
 * Class that represents a valid configuration for json web tokens with HMAC protection.
 * @param algorithm Token algorithm. It must be one of these: "HS256", "HS384", "HS512".
 * @param secret Shared secret for token validation.
 *               For HS256 must be a 256+ bit (32+ byte) secret.
 *               For HS384 must be a 384+ bit (48+ byte) secret.
 *               For HS512 must be a 512+ bit (64+ byte) secret.
 */
case class HmacConfig( algorithm: String, secret: String, defaultExpTime: TimeDuration ) {

  require( List( "HS256", "HS384", "HS512" ).contains( algorithm ), "Invalid algorithm for HMAC generator" )

  algorithm match {
    case "HS256" => require( secret.getBytes( "UTF-8" ).length >= 32, s"Invalid secret length for $algorithm algorithm" )
    case "HS384" => require( secret.getBytes( "UTF-8" ).length >= 48, s"Invalid secret length for $algorithm algorithm" )
    case _       => require( secret.getBytes( "UTF-8" ).length >= 64, s"Invalid secret length for $algorithm algorithm" )
  }

}

object HmacConfig {

  // Implicit value reader for ficus config
  implicit val reader: ValueReader[ HmacConfig ] = ValueReader.relative { config =>
    HmacConfig(
      config.as[ String ]( "algorithm" ),
      config.as[ String ]( "secret" ),
      config.as[ TimeDuration ]( "default-expiration-time" )
    )
  }

}
