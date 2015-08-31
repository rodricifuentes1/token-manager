## Token manager
Token manager is a configurable JWT generator library developed in scala on top of [Nimbus JWT library](http://connect2id.com/products/nimbus-jose-jwt). It encapsulates all functionality needed to generate Json web tokens making it easy to re-use them in any project
## Usage
### Generate a JWT with HMAC protection
* Provide basic configuration in your `application.conf` file
```scala
co.rc.tokenmanager {
  hmac {
    algorithm = "HS512" // ALLOWED VALUES: HS256, HS384, HS512
    secret = "o5ejtcyqTRKMYkhn7KLS6xAU0p4q5OqMnD4gkvzGXN90LQUnrwJQDvRCtb2kP8wg" // For HS256 must be a 256+ bit (32+ byte) secret. For HS384 must be a 384+ bit (48+ byte) secret. For HS512 must be a 512+ bit (64+ byte) secret.
    default-expiration-time {
      unit = "minutes" // ALLOWED VALUES: s, second, seconds, m, minute, minutes, h, hour, hours, d, day, days, w, week, weeks
      length = 30
    }
  }
}
```
* Create an instance of `AsyncHmacGenerator`
```scala
  // Provide an implicit execution context
  implicit val executionContext: ExecutionContext = Implicits.global
  
  // Provide an implicit configuration
  implicit val config = ConfigFactory.load()
  
  // Create a new instance
  val generator: AsyncHmacGenerator = new AsyncHmacGenerator()
```
* Use the instance
```scala
  ...
  import co.rc.tokenmanager.hmac.base.TimeDuration
  import co.rc.tokenmanager.util.Converters._
  import org.joda.time.DateTime
  ...
  
  val tokenPayload: Map[String, AnyRef] = Map( "id" ~> 1, "gender" ~> "Male", "age" ~> 22)
  val tokenId: String = "1"
  val tokenIssuer: Option[String] = Some("my application")
  val tokenSubject: Option[String] = Some("my subject")
  val tokenAudience: Option[List[String]] = Some( List("audience1", "audience2") )
  val tokenExpirationTime: Option[TimeDuration] = Some( TimeDuration("minutes", 10) )
  val tokenNotBefore: Option[DateTime] = Some( new DateTime().plusDays(1) )
  
  val token: Future[String] = generator.generateToken(
    tokenPayload,
    tokenId, // OPTIONAL PARAMETER. DEFAULT -> java.util.UUID.randomUUID().toString
    tokenIssuer, // OPTIONAL PARAMETER. DEFAULT -> None
    tokenSubject, // OPTIONAL PARAMETER. DEFAULT -> None
    tokenAudience, // OPTIONAL PARAMETER. DEFAULT -> None
    tokenExpirationTime, // OPTIONAL PARAMETER. DEFAULT -> None
    tokenNotBefore // OPTIONAL PARAMETER. DEFAULT -> None
  )
```
### Validate a JWT token
```scala
  // Provide an implicit execution context
  implicit val executionContext: ExecutionContext = Implicits.global
  
  // Provide an implicit configuration
  implicit val config = ConfigFactory.load()

  // Token to validate
  val token: String = "eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA"
  
  // Default validation
  val valid: Future[Boolean] = AsyncHmacGenerator.validateToken( token )
  
  // Custom validation
  // Optional parameter validateExpirationTime is set to true by default
  // Optional parameter validateNotBeforeDate is set to false by default
  val valid2: Future[Boolean] = AsyncHmacGenerator.validateToken( token, validateExpirationTime = false, validateNotBeforeDate = true )
```
### Get token claims
```scala
  // Provide an implicit execution context
  implicit val executionContext: ExecutionContext = Implicits.global
  
  // Provide an implicit configuration
  implicit val config = ConfigFactory.load()
  
  // Token
  val token: String = "eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA"
  
  // Get all claims
  val allClaims: Future[ReadOnlyJWTClaimsSet] = AsyncHmacGenerator.getJWTClaims( token )
  
  // Get a specific claim
  val specificClaim: Future[Option[AnyRef]] = AsyncHmacGenerator.getJwtClaim( token, "claimName" )
```
## Build this project
1. Clone the repo
2. Execute commands in sbt console: `update, compile`
3. To run tests execute in sbt console: `test`
4. To generate code coverage report execute in sbt console: `coverage, test`

## Test code coverage - 100%
