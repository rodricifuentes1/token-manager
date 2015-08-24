package co.rc.tokenmanager.util

/**
 * Object that contains utility converters
 */
object Converters {

  class StringArrow( s: String ) {
    def ~>( a: Any ) = s -> a.asInstanceOf[ AnyRef ]
  }

  implicit def string_has_arrow( s: String ) = new StringArrow( s )

}
