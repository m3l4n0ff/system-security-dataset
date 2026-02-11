package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

// T1083 - Systematic API enumeration and reconnaissance
class T1083_APIReconnaissanceSimulation extends Simulation {

  // configuration
  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")

  // http protocol
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .userAgentHeader("Python-requests/2.31.0") // Simulating automated tool
    .header("X-Experiment-ID", "attack_api_recon_v1")
    .header("X-Event-Label", "malicious")
    .header("X-Scenario-ID", "T1083_API_DISCOVERY")
    .header("X-Attack-Technique", "T1083")

  // attack scenario: systematic api enumeration
  val apiReconnaissance = scenario("T1083 - API Reconnaissance Attack")
    
    // Phase 1: Discover API structure
    .exec(http("T1083 - Discover API Root")
      .get("/api/v3")
      .check(status.is(200)))
    .pause(500.milliseconds, 1.second)
    
    // Phase 2: Enumerate all projects
    .exec(http("T1083 - Enum All Projects")
      .get("/api/v3/projects")
      .queryParam("pageSize", "100") // Get max results
      .check(status.is(200))
      .check(jsonPath("$._embedded.elements[*].id").findAll.saveAs("projectIds")))
    .pause(1.second)
    
    // Phase 3: Enumerate all users
    .exec(http("T1083 - Enum All Users")
      .get("/api/v3/users")
      .queryParam("pageSize", "100")
      .check(status.is(200)))
    .pause(1.second)
    
    // Phase 4: Enumerate work package types
    .exec(http("T1083 - Enum Work Package Types")
      .get("/api/v3/types")
      .check(status.is(200)))
    .pause(500.milliseconds)
    
    // Phase 5: Enumerate statuses
    .exec(http("T1083 - Enum Statuses")
      .get("/api/v3/statuses")
      .check(status.is(200)))
    .pause(500.milliseconds)
    
    // Phase 6: Enumerate priorities
    .exec(http("T1083 - Enum Priorities")
      .get("/api/v3/priorities")
      .check(status.is(200)))
    .pause(500.milliseconds)
    
    // Phase 7: Enumerate roles and permissions
    .exec(http("T1083 - Enum Roles")
      .get("/api/v3/roles")
      .check(status.is(200)))
    .pause(1.second)
    
    // Phase 8: Enumerate groups
    .exec(http("T1083 - Enum Groups")
      .get("/api/v3/groups")
      .check(status.is(200)))
    .pause(1.second)
    
    // Phase 9: Try to enumerate memberships (permissions mapping)
    .exec(http("T1083 - Enum Memberships")
      .get("/api/v3/memberships")
      .queryParam("pageSize", "100")
      .check(status.in(200, 403))) // May be forbidden
    .pause(1.second)
    
    // Phase 10: Enumerate work packages (all data)
    .exec(http("T1083 - Enum All Work Packages")
      .get("/api/v3/work_packages")
      .queryParam("pageSize", "100")
      .queryParam("offset", "0")
      .check(status.is(200)))
    .pause(2.seconds)
    
    // Phase 11: Try accessing admin endpoints
    .exec(http("T1083 - Probe Admin API")
      .get("/api/v3/admin/settings")
      .check(status.in(200, 401, 403)))
    .pause(1.second)
    
    // Phase 12: Enumerate attachments/files
    .exec(http("T1083 - Enum Attachments")
      .get("/api/v3/attachments")
      .queryParam("pageSize", "100")
      .check(status.in(200, 403)))
    .pause(1.second)
    
    // Phase 13: Enumerate queries (saved filters)
    .exec(http("T1083 - Enum Queries")
      .get("/api/v3/queries")
      .check(status.is(200)))
    .pause(500.milliseconds)
    
    // Phase 14: Enumerate custom fields
    .exec(http("T1083 - Enum Custom Fields")
      .get("/api/v3/custom_fields")
      .check(status.in(200, 403)))
    .pause(500.milliseconds)
    
    // Phase 15: Deep dive - enumerate project details for each discovered project
    .foreach("${projectIds}", "projectId") {
      exec(http("T1083 - Deep Enum Project ${projectId}")
        .get("/api/v3/projects/${projectId}")
        .check(status.in(200, 404)))
      .pause(200.milliseconds)
      
      .exec(http("T1083 - Enum Project ${projectId} Members")
        .get("/api/v3/projects/${projectId}/memberships")
        .check(status.in(200, 403, 404)))
      .pause(200.milliseconds)
      
      .exec(http("T1083 - Enum Project ${projectId} Work Packages")
        .get("/api/v3/projects/${projectId}/work_packages")
        .queryParam("pageSize", "50")
        .check(status.in(200, 404)))
      .pause(200.milliseconds)
    }

  // attack execution - single attacker, methodical enumeration
  setUp(
    apiReconnaissance.inject(
      atOnceUsers(1)
    )
  ).protocols(httpProtocol)
    .maxDuration(15.minutes)
}