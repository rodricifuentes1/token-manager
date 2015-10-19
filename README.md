## Token manager
Token manager is a configurable JWT generator library developed in scala on top of [Nimbus JWT library](http://connect2id.com/products/nimbus-jose-jwt). It encapsulates all functionality needed to generate Json web tokens making it easy to re-use it in any project
## Usage
### Adding the dependency
* Modify your `build.sbt` file
```
  resolvers += Resolver.bintrayRepo("rodricifuentes1", "RC-releases")
  libraryDependencies += "co.rc" %% "token-manager" % "1.1"
```
* You can also download the compiled `jar file` here [ ![Download](https://api.bintray.com/packages/rodricifuentes1/RC-releases/token-manager/images/download.svg) ](https://bintray.com/rodricifuentes1/RC-releases/token-manager/_latestVersion)

### Generate a JWT with HMAC protection
* Provide required configuration in your `application.conf` file
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
* You can provide default data for token generation in your `application.conf` file using 'data' config key
```scala
co.rc.tokenmanager {
  hmac {
    algorithm = ...
    secret = ...
    default-expiration-time {
      unit = ...
      length = ...
    }
    data {
      issuer = "test-issuer"
      subject = "test-subject"
      audience = ["aud1", "aud2"]
    }
  }
}
```
* Create an instance of `AsyncHmacGenerator`
```scala
  // Create a new instance.
  // Configuration will be loaded automatically using ConfigFactory.load() method
  val generator: AsyncHmacGenerator = new AsyncHmacGenerator()
  
  // You can also provide a custom typesafe config
  val config: Config = ConfigFactory.load( "my-custom-config.conf" )
  val generator: AsyncHmacGenerator = new AsyncHmacGenerator( config )
```
* Use the instance
```scala
  ...
  import co.rc.tokenmanager.hmac.base.TimeDuration
  import co.rc.tokenmanager.util.Converters._
  import org.joda.time.DateTime
  ...
  
  // Provide an execution context
  implicit val ec: ExecutionContext = Implicits.global
  
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
    tokenIssuer, // OPTIONAL PARAMETER. DEFAULT -> issuer provided in optional config
    tokenSubject, // OPTIONAL PARAMETER. DEFAULT -> subject provided in optional config
    tokenAudience, // OPTIONAL PARAMETER. DEFAULT -> audience provided in optional config
    tokenExpirationTime, // OPTIONAL PARAMETER. DEFAULT -> default-expiration-time provided in required config
    tokenNotBefore // OPTIONAL PARAMETER. DEFAULT -> none
  )
```
### Validate a JWT token
```scala
  // Provide an implicit execution context
  implicit val executionContext: ExecutionContext = Implicits.global

  // Token to validate
  val token: String = "eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA"
  
  // Default validation
  // This will load automatically configuration using ConfigFactory.load()
  val valid: Future[Boolean] = AsyncHmacGenerator.validateToken( token )
  
  // Custom validation
  // Optional parameter validateExpirationTime is set to true by default
  // Optional parameter validateNotBeforeDate is set to false by default
  val valid2: Future[Boolean] = AsyncHmacGenerator.validateToken( token, validateExpirationTime = false, validateNotBeforeDate = true )
  
  // You can also provide a custom typesafe config
  val config: Config = ConfigFactory.load( "my-custom-config.conf" )
  val valid: Future[Boolean] = AsyncHmacGenerator.validateToken( token, conf = config )
```
### Get token claims
```scala
  // Provide an implicit execution context
  implicit val executionContext: ExecutionContext = Implicits.global
  
  // Token
  val token: String = "eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA"
  
  // Get all claims
  // This will load automatically configuration using ConfigFactory.load()
  val allClaims: Future[ReadOnlyJWTClaimsSet] = AsyncHmacGenerator.getJWTClaims( token )
  
  // Get a specific claim
  // This will load automatically configuration using ConfigFactory.load()
  val specificClaim: Future[Option[AnyRef]] = AsyncHmacGenerator.getJwtClaim( token, "claimName" )
  
  // You can also provide a custom typesafe config
  val config: Config = ConfigFactory.load( "my-custom-config.conf" )
  val allClaims: Future[ReadOnlyJWTClaimsSet] = AsyncHmacGenerator.getJWTClaims( token, conf = config )
  val specificClaim: Future[Option[AnyRef]] = AsyncHmacGenerator.getJwtClaim( token, "claimName", conf = config )
```
## Build this project
1. Clone the repo
2. Execute commands in sbt console: `update, compile`
3. To run tests execute in sbt console: `test`
4. To generate code coverage report execute in sbt console: `coverage, test`

## Test code coverage - 100%
## Changelog
v1.1 (current)
* Removed implicit config parameter for AsyncHmacGenerator class constructor
* Removed implicit config parameter for AsyncHmacGenerator object methods
* Added generation static options via typesafe config

[v1.0](https://github.com/rodricifuentes1/token-manager/tree/v1.0) - First release
