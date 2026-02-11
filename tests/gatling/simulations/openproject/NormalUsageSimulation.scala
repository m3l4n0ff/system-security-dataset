package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

// Normal user baseline traffic simulation
class NormalUsageSimulation extends Simulation {

  // configuration
  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")
  val users = Integer.getInteger("users", 10)
  val duration = Integer.getInteger("duration", 300).seconds // 5 minutes

  // http protocol
  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("text/html,application/json,*/*")
    .acceptEncodingHeader("gzip, deflate")
    .acceptLanguageHeader("en-US,en;q=0.5")
    .userAgentHeader("Mozilla/5.0 (Normal User Simulation)")
    .header("X-Experiment-ID", "baseline_normal_v1")
    .header("X-Event-Label", "normal")

  // feeders - user credentials
  val validUsers = Array(
    Map("username" -> "admin", "password" -> "admin"),
    Map("username" -> "user1", "password" -> "password1"),
    Map("username" -> "user2", "password" -> "password2"),
    Map("username" -> "project_manager", "password" -> "pm123"),
    Map("username" -> "developer", "password" -> "dev123")
  ).circular

  // scenario: normal user workflow
  val normalUserFlow = scenario("Normal User Workflow")
    .feed(validUsers)
    
    // Step 1: Visit homepage
    .exec(http("Homepage")
      .get("/")
      .check(status.is(200)))
    .pause(2, 4)
    
    // Step 2: Go to login page
    .exec(http("Login Page")
      .get("/login")
      .check(status.is(200))
      .check(css("input[name='authenticity_token']", "value").saveAs("csrfToken")))
    .pause(1, 3)
    
    // Step 3: Authenticate with valid credentials
    .exec(http("Login Submit")
      .post("/login")
      .formParam("username", "${username}")
      .formParam("password", "${password}")
      .formParam("authenticity_token", "${csrfToken}")
      .check(status.in(200, 302)))
    .pause(3, 6)
    
    // Step 4: View projects list
    .exec(http("Projects List")
      .get("/projects")
      .check(status.is(200)))
    .pause(2, 5)
    
    // Step 5: Open specific project
    .exec(http("Open Project")
      .get("/projects/demo-project")
      .check(status.in(200, 404))) // 404 if doesn't exist
    .pause(3, 7)
    
    // Step 6: View work packages
    .exec(http("Work Packages")
      .get("/projects/demo-project/work_packages")
      .check(status.in(200, 404)))
    .pause(4, 8)
    
    // Step 7: API - List projects
    .exec(http("API - List Projects")
      .get("/api/v3/projects")
      .header("Accept", "application/json")
      .check(status.is(200)))
    .pause(2, 4)
    
    // Step 8: API - Get user details
    .exec(http("API - Current User")
      .get("/api/v3/users/me")
      .header("Accept", "application/json")
      .check(status.is(200)))
    .pause(3, 6)
    
    // Step 9: Search functionality
    .exec(http("Search")
      .get("/search?q=task")
      .check(status.is(200)))
    .pause(2, 5)
    
    // Step 10: View account settings
    .exec(http("My Account")
      .get("/my/account")
      .check(status.is(200)))
    .pause(2, 4)
    
    // Step 11: Logout
    .exec(http("Logout")
      .post("/logout")
      .check(status.in(200, 302)))

  // load profile
  setUp(
    normalUserFlow.inject(
      rampUsers(users).during(30.seconds), // Ramp up over 30s
      constantUsersPerSec(users / 10).during(duration - 30.seconds) // Steady state
    )
  ).protocols(httpProtocol)
}