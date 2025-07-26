const http = require("http");
const { performance } = require("perf_hooks");

class RegistrationLoadTest {
  constructor() {
    this.results = {
      requests: 0,
      errors: 0,
      totalTime: 0,
      responseTypes: {},
      avgResponseTime: 0,
      errorDetails: {}
    };
    this.userCounter = 0;
  }

  async runTest(url, concurrency = 10, duration = 30) {
    console.log(`Testing ${url} with ${concurrency} concurrent users for ${duration}s`);
    console.log("Testing user registration endpoint with unique users...\n");
    
    const startTime = performance.now();
    const endTime = startTime + (duration * 1000);
    
    const workers = [];
    for (let i = 0; i < concurrency; i++) {
      workers.push(this.worker(url, endTime, i));
    }
    
    await Promise.all(workers);
    
    const totalTestTime = (performance.now() - startTime) / 1000;
    this.printResults(totalTestTime);
  }

  async worker(url, endTime, workerId) {
    let requestCount = 0;
    
    while (performance.now() < endTime) {
      const startTime = performance.now();
      
      try {
        const userData = this.generateUniqueUser(workerId, requestCount);
        const response = await this.makeRegistrationRequest(url, userData);
        const responseTime = performance.now() - startTime;
        
        this.results.requests++;
        this.results.totalTime += responseTime;
        this.results.responseTypes[response.statusCode] = 
          (this.results.responseTypes[response.statusCode] || 0) + 1;
          
        requestCount++;
        
        // Add small delay to prevent overwhelming the server
        await this.sleep(100);
        
      } catch (error) {
        this.results.errors++;
        const errorType = error.message || "Unknown Error";
        this.results.errorDetails[errorType] = 
          (this.results.errorDetails[errorType] || 0) + 1;
      }
    }
  }

  generateUniqueUser(workerId, requestCount) {
    const timestamp = Date.now();
    const uniqueId = `${workerId}_${requestCount}_${timestamp}`;
    
    return {
      firstName: `TestUser${uniqueId}`,
      lastName: `LoadTest${workerId}`,
      email: `testuser_${uniqueId}@loadtest.com`,
      password: "TestPassword123!",
      confirmPassword: "TestPassword123!",
      role: "user"
    };
  }

  makeRegistrationRequest(url, userData) {
    return new Promise((resolve, reject) => {
      const urlParts = new URL(url);
      const postData = JSON.stringify(userData);
      
      const options = {
        hostname: urlParts.hostname,
        port: urlParts.port || 3000,
        path: urlParts.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData)
        },
        timeout: 10000
      };

      const req = http.request(options, (res) => {
        let data = "";
        res.on("data", chunk => data += chunk);
        res.on("end", () => {
          res.body = data;
          resolve(res);
        });
      });

      req.on("error", (error) => {
        reject(new Error(`Request Error: ${error.message}`));
      });

      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Request Timeout"));
      });

      req.setTimeout(10000);
      req.write(postData);
      req.end();
    });
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  printResults(testDuration) {
    console.log("\n" + "=".repeat(60));
    console.log("           REGISTRATION LOAD TEST RESULTS");
    console.log("=".repeat(60));
    
    const successfulRequests = this.results.requests - this.results.errors;
    const successRate = this.results.requests > 0 ? 
      (successfulRequests / this.results.requests * 100) : 0;
    const rps = this.results.requests / testDuration;
    const avgResponseTime = this.results.requests > 0 ? 
      this.results.totalTime / this.results.requests : 0;

    console.log(`📊 Total Requests: ${this.results.requests}`);
    console.log(`✅ Successful: ${successfulRequests}`);
    console.log(`❌ Errors: ${this.results.errors}`);
    console.log(`📈 Success Rate: ${successRate.toFixed(2)}%`);
    console.log(`⚡ Requests/Second: ${rps.toFixed(2)}`);
    console.log(`⏱️  Average Response Time: ${avgResponseTime.toFixed(2)}ms`);
    console.log(`⏰ Test Duration: ${testDuration.toFixed(2)}s`);
    
    console.log("\n📋 Response Status Codes:");
    Object.entries(this.results.responseTypes).forEach(([code, count]) => {
      const percentage = (count / this.results.requests * 100).toFixed(1);
      console.log(`   ${code}: ${count} (${percentage}%)`);
    });

    if (Object.keys(this.results.errorDetails).length > 0) {
      console.log("\n🚨 Error Details:");
      Object.entries(this.results.errorDetails).forEach(([error, count]) => {
        console.log(`   ${error}: ${count}`);
      });
    }

    // Performance rating specific to registration endpoints
    console.log("\n" + "=".repeat(60));
    console.log("           PERFORMANCE ANALYSIS");
    console.log("=".repeat(60));
    
    if (successRate >= 95 && rps > 50 && avgResponseTime < 200) {
      console.log("🟢 EXCELLENT - Registration system is production-ready!");
      console.log("   High throughput with excellent reliability");
    } else if (successRate >= 90 && rps > 25 && avgResponseTime < 500) {
      console.log("🟡 GOOD - Registration system performs well");
      console.log("   Minor optimizations may improve performance");
    } else if (successRate >= 80 && rps > 10 && avgResponseTime < 1000) {
      console.log("🟠 AVERAGE - Registration system needs optimization");
      console.log("   Consider database indexing and connection pooling");
    } else {
      console.log("🔴 POOR - Registration system requires major improvements");
      console.log("   Check database performance, server resources, and code efficiency");
    }

    // Specific recommendations for registration endpoints
    console.log("\n💡 Recommendations:");
    if (this.results.responseTypes["409"]) {
      console.log("   • High number of 409 conflicts - email validation working correctly");
    }
    if (this.results.responseTypes["400"]) {
      console.log("   • 400 errors detected - check input validation logic");
    }
    if (avgResponseTime > 500) {
      console.log("   • Slow response times - optimize database queries and password hashing");
    }
    if (successRate < 95) {
      console.log("   • Low success rate - investigate error handling and server capacity");
    }
  }
}

function parseArguments() {
  const args = process.argv.slice(2);
  const config = {
    url: "http://localhost:3000/api/auth/register",
    concurrency: 10,
    duration: 30
  };

  args.forEach((arg, index) => {
    if (arg.startsWith("http")) {
      config.url = arg;
    } else if (arg.includes("concurrency=") || arg.includes("-c=")) {
      config.concurrency = parseInt(arg.split("=")[1]) || 10;
    } else if (arg.includes("duration=") || arg.includes("-d=")) {
      config.duration = parseInt(arg.split("=")[1]) || 30;
    } else if (!isNaN(parseInt(arg))) {
      if (index === 1) config.concurrency = parseInt(arg);
      if (index === 2) config.duration = parseInt(arg);
    }
  });

  return config;
}

function showUsage() {
  console.log("\n📋 REGISTRATION LOAD TESTER");
  console.log("=".repeat(40));
  console.log("Usage: node registration-load-test.js [url] [concurrency] [duration]");
  console.log("\nExamples:");
  console.log("  node registration-load-test.js");
  console.log("  node registration-load-test.js http://localhost:3000/api/auth/register 20 60");
  console.log("  node registration-load-test.js concurrency=50 duration=120");
  console.log("\nDefault: localhost:3000/api/auth/register, 10 concurrent users, 30 seconds\n");
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    showUsage();
    return;
  }

  const config = parseArguments();
  
  console.log("🚀 Starting Registration Load Test...");
  console.log(`URL: ${config.url}`);
  console.log(`Concurrency: ${config.concurrency} users`);
  console.log(`Duration: ${config.duration} seconds`);
  
  const tester = new RegistrationLoadTest();
  
  try {
    await tester.runTest(config.url, config.concurrency, config.duration);
  } catch (error) {
    console.error("\n❌ Test failed:", error.message);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on("SIGINT", () => {
  console.log("\n\n⏹️  Test interrupted by user");
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("\n\n⏹️  Test terminated");
  process.exit(0);
});

main().catch(console.error);
