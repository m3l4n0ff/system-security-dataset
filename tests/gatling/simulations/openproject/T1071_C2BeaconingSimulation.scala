package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

// T1071.001 - C2 beaconing over HTTP API endpoints
class T1071_C2BeaconingSimulation extends Simulation {

  // configuration
  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")
  val beaconDuration = Integer.getInteger("duration", 600).seconds // 10 minutes
  val beaconInterval = 30.seconds // Beacon every 30 seconds

  // http protocol - mimicking legitimate traffic
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .userAgentHeader("OpenProjectBot/1.0") // Looks like a legitimate bot
    .header("X-Experiment-ID", "attack_c2_beaconing_v1")
    .header("X-Event-Label", "malicious")
    .header("X-Scenario-ID", "T1071_C2_BEACONING")
    .header("X-Attack-Technique", "T1071.001")

  // Valid credentials for authenticated C2 channel
  val compromisedAccount = Map(
    "username" -> "admin",
    "password" -> "admin"
  )

  // attack scenario: c2 beaconing
  val c2BeaconingAttack = scenario("T1071 - C2 Beaconing Attack")
    
    // Initial authentication (compromised account)
    .exec(http("C2 - Initial Auth")
      .get("/login")
      .check(status.is(200))
      .check(css("input[name='authenticity_token']", "value").saveAs("csrfToken")))
    .pause(1.second)
    
    .exec(http("C2 - Login with Compromised Account")
      .post("/login")
      .formParam("username", compromisedAccount("username"))
      .formParam("password", compromisedAccount("password"))
      .formParam("authenticity_token", "${csrfToken}")
      .check(status.in(200, 302)))
    .pause(2.seconds)
    
    // Main C2 beaconing loop - runs for specified duration
    .asLongAs(session => session.elapsed < beaconDuration.toMillis) {
      
      // Beacon 1: Check for commands (disguised as checking notifications)
      exec(http("C2 Beacon - Check Notifications")
        .get("/api/v3/notifications")
        .header("X-C2-Beacon", "check_in")
        .check(status.is(200)))
      .pause(beaconInterval)
      
      // Beacon 2: Exfiltrate project data (disguised as normal query)
      .exec(http("C2 Beacon - Exfiltrate Projects")
        .get("/api/v3/projects")
        .queryParam("pageSize", "100")
        .header("X-C2-Beacon", "exfil_projects")
        .check(status.is(200))
        .check(bodyString.saveAs("exfilData")))
      .pause(beaconInterval)
      
      // Beacon 3: Exfiltrate user data
      .exec(http("C2 Beacon - Exfiltrate Users")
        .get("/api/v3/users")
        .queryParam("pageSize", "100")
        .header("X-C2-Beacon", "exfil_users")
        .check(status.is(200)))
      .pause(beaconInterval)
      
      // Beacon 4: Check specific work package (command channel)
      .exec(http("C2 Beacon - Command Channel Check")
        .get("/api/v3/work_packages/1")
        .header("X-C2-Beacon", "cmd_check")
        .check(status.in(200, 404)))
      .pause(beaconInterval)
      
      // Beacon 5: Exfiltrate work packages
      .exec(http("C2 Beacon - Exfiltrate Work Packages")
        .get("/api/v3/work_packages")
        .queryParam("pageSize", "50")
        .queryParam("filters", """[{"status":{"operator":"*","values":[]}}]""")
        .header("X-C2-Beacon", "exfil_workpackages")
        .check(status.is(200)))
      .pause(beaconInterval)
      
      // Beacon 6: Exfiltrate attachments/files list
      .exec(http("C2 Beacon - Exfiltrate File Listings")
        .get("/api/v3/attachments")
        .queryParam("pageSize", "100")
        .header("X-C2-Beacon", "exfil_files")
        .check(status.in(200, 403)))
      .pause(beaconInterval)
      
      // Beacon 7: Check queries (could contain commands in custom query names)
      .exec(http("C2 Beacon - Check Queries")
        .get("/api/v3/queries")
        .header("X-C2-Beacon", "cmd_queries")
        .check(status.is(200)))
      .pause(beaconInterval)
      
      // Beacon 8: Heartbeat check (minimal traffic)
      .exec(http("C2 Beacon - Heartbeat")
        .get("/api/v3")
        .header("X-C2-Beacon", "heartbeat")
        .check(status.is(200)))
      .pause(beaconInterval)
    }

  // attack execution - single persistent connection
  setUp(
    c2BeaconingAttack.inject(
      atOnceUsers(1) // Single C2 channel
    )
  ).protocols(httpProtocol)
    .maxDuration(beaconDuration + 1.minute)
}