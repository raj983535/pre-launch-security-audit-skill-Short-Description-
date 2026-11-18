# Stack guide: Java/Spring, .NET, Ruby/Rails, Go, other backends, Flutter and native mobile

## Contents
- Java and Kotlin (Spring Boot)
- .NET (ASP.NET Core)
- Ruby on Rails
- Go
- Other backends (Elixir/Phoenix, Rust, Laravel-like frameworks)
- Flutter and native mobile (iOS/Android)

For each stack, map findings to the numbered checks and run the cross-stack grep ideas from `scripts/quick_scan.py`.

## Java and Kotlin (Spring Boot)
- **Actuator and tooling (11.3).** Spring Boot Actuator endpoints (`/actuator/env`, `heapdump`, `beans`, `mappings`, `loggers`) exposed publicly leak secrets and memory; expose only `health` and secure the rest. Disable devtools, H2 console and Swagger in production.
- **Authorisation (2.1, 3.1, 3.7).** Spring Security config denies by default (`anyRequest().authenticated()`); method security (`@PreAuthorize`) with object-level checks in services; no `permitAll()` on admin paths; CSRF enabled for cookie sessions; check matcher ordering.
- **Injection (4.1, 5.9).** JPA/JDBC with bound parameters (no string-concatenated JPQL/HQL/native queries); no `ObjectInputStream` on untrusted data, Jackson default typing off (`enableDefaultTyping`), XML parsers with external entities disabled (XXE); SpEL/OGNL/template engines never evaluate user input; log libraries are current (the Log4Shell class of bugs lives in dependencies, 10.1).
- **Mass assignment (3.2).** Binding request JSON/forms directly to JPA entities; use DTOs. `@JsonIgnore`/response DTOs for password hashes and internal fields (6.4).
- **Secrets (1.x).** `application.properties/yml` with passwords committed; use env/secret manager, Spring Cloud Config with encryption.
- **Deps (10.1).** `mvn dependency-check:check`, `gradle dependencyCheckAnalyze`, or `trivy fs .`.

## .NET (ASP.NET Core)
- `[Authorize]` globally via fallback policy with `[AllowAnonymous]` only where intended (3.8); resource-based authorisation for ownership (3.1); policies per role (3.7).
- Over-posting (3.2): bind to view models/DTOs, not entities; `[Bind]` allowlists.
- EF Core: `FromSqlRaw`/`ExecuteSqlRaw` with interpolation fail; use `FromSqlInterpolated` or parameters (4.1).
- Anti-forgery tokens on cookie-auth forms (6.5); `BinaryFormatter` and `TypeNameHandling` in Json.NET fail (5.9); Data Protection keys persisted and secret; `appsettings*.json`, user-secrets and connection strings out of source control (1.x); `UseHsts`, `UseHttpsRedirection`, developer exception page off in production (11.2); Swagger gated (11.3); `dotnet list package --vulnerable` (10.1).

## Ruby on Rails
- Strong parameters everywhere (`params.require(:x).permit(...)`), never `permit!` (3.2). `before_action :authenticate_user!` in `ApplicationController` with `skip_before_action` audited (3.8); scope lookups through `current_user.records.find(id)` (3.1); Pundit/CanCanCan policies.
- SQL (4.1): `where("name = '#{x}'")`, `find_by_sql`, `order(params[:sort])`, `pluck(params[:col])` fail; use hash conditions or `?` binds and allowlists.
- Output (5.2): `html_safe`, `raw` reviewed. Dangerous methods (5.7, 5.9): `send`/`public_send`/`constantize` on input, `eval`, `YAML.load` (use `safe_load`), `Marshal.load`, `open(url)`/`Kernel#open` with user strings, `render file:`/`render inline:`.
- CSRF `protect_from_forgery` on; `config.force_ssl = true`; `config.consider_all_requests_local = false`; `secret_key_base`/credentials not committed (1.x); Active Storage direct uploads restricted and variants not user-controlled; `bundle audit`, `brakeman` if available (10.1).

## Go
- `database/sql` with placeholders (`$1`, `?`), never `fmt.Sprintf` into queries (4.1); `html/template` (auto-escapes) not `text/template` for HTML, and no `template.HTML(userInput)` (5.2).
- Path traversal: `filepath.Join` + `filepath.Clean` doesn't stop `..`; check containment; `http.FileServer` on a dedicated dir (5.8). `exec.Command` with args, not `sh -c` (5.7).
- JSON binding with `DisallowUnknownFields`, struct tags excluding sensitive fields (3.2, 6.4); `http.Server` timeouts (`ReadHeaderTimeout`) and `MaxBytesReader` (6.7); goroutine + shared map data races on balances (7.8): use transactions/locks, run `go test -race`.
- `crypto/rand` not `math/rand` for secrets (2.3); `InsecureSkipVerify: true` fails (11.6); `govulncheck ./...` (10.1).

## Other backends
Elixir/Phoenix: `Ecto` fragments with interpolation, `:erlang.binary_to_term` on untrusted data, `plug` CSRF/auth pipelines. Rust: `unsafe` blocks, `sqlx::query` string formatting, `cargo audit`. Any framework: apply the numbered checks directly: routes and auth (2.1), ownership (3.1), input validation (5.1), injection (4.1), config (11.x).

## Flutter and native mobile (also see area 14)
- **Flutter/Dart (14.x).** Tokens in `flutter_secure_storage`, not `shared_preferences` (14.1); no keys in Dart code or `assets/` (14.2); `http://` URLs and `badCertificateCallback => true` fail (14.3); `webview_flutter` restricted to trusted URLs (14.5); release builds with `--obfuscate --split-debug-info` are a speed bump, not security; check `AndroidManifest.xml`/`Info.plist` flags with the scanner.
- **Android native (Kotlin/Java).** `android:exported` on activities/services/receivers/providers only when intended, with permissions; `allowBackup`, `usesCleartextTraffic`, `debuggable` off in release; `network_security_config.xml` without broad trust; `WebView.setJavaScriptEnabled` and `addJavascriptInterface` reviewed; `SharedPreferences` for secrets fails (use EncryptedSharedPreferences/Keystore); ProGuard/R8 enabled; Intent data validated.
- **iOS native (Swift/ObjC).** Keychain for secrets (`kSecAttrAccessible...ThisDeviceOnly` for high sensitivity), not `UserDefaults`; ATS exceptions minimised; URL scheme and Universal Link handlers validate input; `WKWebView` content restricted; no sensitive data in logs/snapshots; Background snapshot hiding for sensitive screens (14.9).
- **Ionic/Capacitor/Cordova.** WebView-based: all web checks (5.2, 6.x) apply plus: restrict `allowNavigation`, CSP in `index.html`, plugin permissions, and treat bundled JS as public (14.2).
