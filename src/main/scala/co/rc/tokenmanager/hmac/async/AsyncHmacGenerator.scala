package co.rc.tokenmanager.hmac.async

import co.rc.tokenmanager.hmac.base.{ HmacConfig, TimeDuration }
import co.rc.tokenmanager.util.TokenException

import com.nimbusds.jwt.{ ReadOnlyJWTClaimsSet, SignedJWT, JWTClaimsSet }
import com.nimbusds.jose.crypto.{ MACVerifier, MACSigner }
import com.nimbusds.jose.{ JOSEObjectType, JWSAlgorithm, JWSHeader, JWSSigner }

import com.typesafe.config.Config

import net.ceedubs.ficus.Ficus._

import org.joda.time.DateTime

import scala.concurrent.{ Future, ExecutionContext }
import scala.collection.JavaConversions._
import scala.util.{ Failure, Success, Try }

class AsyncHmacGenerator()( implicit executionContext: ExecutionContext, conf: Config ) {

  /**
   * Method that generates a JWT with HMAC protection
   * @param payload Token json payload
   * @param id Token id
   * @param issuer Token issuer - OPTIONAL
   * @param subject Token subject - OPTIONAL
   * @param audience Token audience - OPTIONAL
   * @param expirationTime Token expiration time - OPTIONAL
   * @param notBefore Token minimum date of validity - OPTIONAL
   * @return A Future with generated token
   */
  def generateToken( payload: Map[ String, AnyRef ],
    id: String = java.util.UUID.randomUUID().toString,
    issuer: Option[ String ] = None,
    subject: Option[ String ] = None,
    audience: Option[ List[ String ] ] = None,
    expirationTime: Option[ TimeDuration ] = None,
    notBefore: Option[ DateTime ] = None ): Future[ String ] = Future {

    // Load configuration for HMAC tokens
    val config: HmacConfig = conf.as[ HmacConfig ]( "co.rc.tokenmanager.hmac" )

    // Actual DateTime
    val now: DateTime = DateTime.now

    // Init token claimsSet
    val claimsSet: JWTClaimsSet = new JWTClaimsSet()

    // Set token claims
    // More info http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4
    issuer.map( iss => claimsSet.setIssuer( iss ) )
    subject.map( sb => claimsSet.setSubject( sb ) )
    audience.map( aud => claimsSet.setAudience( aud ) )
    expirationTime match {
      case Some( et ) =>
        if ( notBefore.isDefined ) claimsSet.setExpirationTime( getExpirationDate( notBefore.get, et ).toDate )
        else claimsSet.setExpirationTime( getExpirationDate( now, et ).toDate )
      case None =>
        if ( notBefore.isDefined ) claimsSet.setExpirationTime( getExpirationDate( notBefore.get, config.defaultExpTime ).toDate )
        else claimsSet.setExpirationTime( getExpirationDate( now, config.defaultExpTime ).toDate )
    }
    notBefore.map( nb => claimsSet.setNotBeforeTime( nb.toDate ) )

    // Obligatory claims
    claimsSet.setIssueTime( now.toDate )
    claimsSet.setJWTID( id )

    // Set token custom claims
    claimsSet.setCustomClaims( payload )

    // Token header with "TYP" param included
    val header: JWSHeader = new JWSHeader(
      getAlgorithm( config.algorithm ),
      new JOSEObjectType( "JWT" ),
      null, null, null, null, null, null, null, null, null, null, null
    )

    // HMAC signer
    val signer: JWSSigner = new MACSigner( config.secret.getBytes( "UTF-8" ) )
    val signedJWT: SignedJWT = new SignedJWT( header, claimsSet )

    signedJWT.sign( signer )
    signedJWT.serialize()
  }

  // ----------------------
  // Utility methods
  // ----------------------

  /**
   * Method that calculates token expiration time date
   * @param baseDate Base date to do calculations
   * @param time Token expiration time
   * @return Calculated expiration date
   */
  private def getExpirationDate( baseDate: DateTime, time: TimeDuration ): DateTime = {
    time.unit match {
      case "s" | "second" | "seconds" => baseDate.plusSeconds( time.length )
      case "m" | "minute" | "minutes" => baseDate.plusMinutes( time.length )
      case "h" | "hour" | "hours"     => baseDate.plusHours( time.length )
      case "d" | "day" | "days"       => baseDate.plusDays( time.length )
      case _                          => baseDate.plusWeeks( time.length ) // "w", "week", "weeks"
    }
  }

  /**
   * Method that maps token String algorithm into JWSAlgorithm.
   * Default algorithm is set to HS512
   * @param algorithm Selected algorithm
   * @return Mapped algorithm
   */
  private def getAlgorithm( algorithm: String ): JWSAlgorithm = {
    algorithm match {
      case "HS256" => JWSAlgorithm.HS256
      case "HS384" => JWSAlgorithm.HS384
      case _       => JWSAlgorithm.HS512
    }
  }

}

object AsyncHmacGenerator {

  /**
   * Method that validates a token
   * @param token Token to validate
   * @param validateExpirationTime Boolean that indicates if it must validate token expiration time. Default is true.
   * @param validateNotBeforeDate Boolean that indicates if it must validate token not before date. Default is true.
   * @param executionContext implicit execution context for future management
   * @param conf Implicit app configuration
   * @return A future with a Boolean inside.
   */
  def validateToken( token: String,
    validateExpirationTime: Boolean = true,
    validateNotBeforeDate: Boolean = true )( implicit executionContext: ExecutionContext, conf: Config ): Future[ Boolean ] = Future {

    // Token structure validation
    // Can be failure if token is not well-formed
    val structureCheck: Try[ ( SignedJWT, Boolean ) ] = for {
      signedJwt <- parseToken( token )
      verifier <- getVerifier()
      valid <- verify( signedJwt, verifier )
    } yield ( signedJwt, valid )

    structureCheck match {
      case Failure( ex ) => throw ex
      case Success( data ) =>
        if ( !data._2 ) false
        else {
          val exp: java.util.Date = data._1.getJWTClaimsSet.getExpirationTime
          val nb: java.util.Date = data._1.getJWTClaimsSet.getNotBeforeTime
          ( validateExpirationTime, validateNotBeforeDate ) match {
            case ( true, true )   => !hasExpired( exp ) && !isUsedBeforeTime( nb )
            case ( true, false )  => !hasExpired( exp )
            case ( false, true )  => !isUsedBeforeTime( nb )
            case ( false, false ) => true
          }
        }
    }

  }

  /**
   * Method that retrieves token claims set object
   * @param token Token to parse
   * @param executionContext implicit execution context for future management
   * @param conf Implicit app configuration
   * @return A Future with token claims if token is well formed
   *         An exception otherwise
   */
  def getJWTClaims( token: String )( implicit executionContext: ExecutionContext, conf: Config ): Future[ ReadOnlyJWTClaimsSet ] = Future {

    // Get claims set
    val claimsSet: Try[ ReadOnlyJWTClaimsSet ] = for {
      signedJwt <- parseToken( token )
    } yield signedJwt.getJWTClaimsSet

    claimsSet match {
      case Success( claims ) => claims
      case Failure( ex )     => throw ex
    }

  }

  /**
   * Method that retrieves a specific claim from token claims
   * @param token Token to parse
   * @param claimName Claim name to retrieve
   * @param executionContext implicit execution context for future management
   * @param conf Implicit app configuration
   * @return A Future with an Option of required claim as an AnyRef instance
   *         Throws exception if token is not valid
   */
  def getJwtClaim( token: String,
    claimName: String )( implicit executionContext: ExecutionContext, conf: Config ): Future[ Option[ AnyRef ] ] = Future {

    // Get claims set
    val claimsSet: Try[ Option[ AnyRef ] ] = for {
      signedJwt <- parseToken( token )
    } yield {
      val claim: AnyRef = signedJwt.getJWTClaimsSet.getClaim( claimName )
      if ( claim != null ) Some( claim ) else None
    }

    claimsSet match {
      case Success( claim ) => claim
      case Failure( ex )    => throw ex
    }
  }

  // ----------------------
  // Utility methods
  // ----------------------

  /**
   * Method that parse and verify token structure
   * @param token Token to parse
   * @return A Try with a SignetJWT instance inside
   *         Throws ParseException if token is invalid
   */
  private def parseToken( token: String ) = Try {
    SignedJWT.parse( token )
  }

  /**
   * Method that creates a new HMACVerifier
   * @param conf Implicit configuration loaded
   * @return A Try with MACVerifier instance inside
   *         Throws IllegalArgumentException if configuration is invalid
   */
  private def getVerifier()( implicit conf: Config ): Try[ MACVerifier ] = Try {
    val config: HmacConfig = conf.as[ HmacConfig ]( "co.rc.tokenmanager.hmac" )
    new MACVerifier( config.secret )
  }

  /**
   * Method that verifies validity of a signed JWT given a secret key
   * @param signedJWT SignedJWT to verify
   * @param verifier Verifier with secret key
   * @return A Try with a Boolean inside
   *         Throws JOSEException if token is invalid
   */
  private def verify( signedJWT: SignedJWT, verifier: MACVerifier ): Try[ Boolean ] = Try {
    signedJWT.verify( verifier )
  }

  /**
   * Method that validates if token has expired
   * @param expirationTime Token expiration time milliseconds
   * @return A Boolean
   *         True if token has expired
   *         False otherwise
   */
  private def hasExpired( expirationTime: java.util.Date ): Boolean = {
    val now: DateTime = new DateTime()
    val expirationDate: DateTime = new DateTime( expirationTime )
    now.isAfter( expirationDate )
  }

  /**
   * Method that validates if token is used before authorized date
   * @param notBeforeTime Token not before time milliseconds
   * @return A Boolean
   *         True if token is not authorized to be used now
   *         False otherwise
   *         Throws TokenException if notBefore param is null
   */
  private def isUsedBeforeTime( notBeforeTime: java.util.Date ): Boolean = {
    if ( notBeforeTime == null ) throw new TokenException( "Not before time is not defined" )
    else {
      val now: DateTime = new DateTime()
      val notBeforeDate: DateTime = new DateTime( notBeforeTime )
      now.isBefore( notBeforeDate )
    }
  }

}
