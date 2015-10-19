package co.rc.tokenmanager.hmac.util

import com.typesafe.config.Config
import com.typesafe.config.ConfigException._
import com.typesafe.config.ConfigValueType._

import net.ceedubs.ficus.readers.ValueReader

import org.joda.time.DateTime

/**
 * Contains ficus reader for joda DateTime
 */
object DateTimeReader {

  // Ficus reader for joda time
  implicit val reader: ValueReader[ DateTime ] = new ValueReader[ DateTime ] {
    def read( config: Config, path: String ): DateTime = config.getValue( path ).valueType() match {
      case NUMBER => new DateTime( config.getLong( path ) )
      case STRING => try new DateTime( config.getString( path ) ) catch {
        case e: IllegalArgumentException => throw new BadValue( path, e.getMessage, e )
      }
      case t => throw new WrongType( config.origin, path,
        "NUMBER(milliseconds) or STRING(ISO-8601)", t.toString )
    }
  }

}
