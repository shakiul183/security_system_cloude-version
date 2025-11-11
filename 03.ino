/*
 Full ESP32 project:
 - Boot beep (10 cycles of 1s ON + 100ms OFF) before anything else
 - After beep: start WiFi AP, then create FreeRTOS tasks:
     Core0: web server + auth
     Core1: sensors & buzzer event handling
 - Signup, Login, Dashboard (HTML served from device)
 - EEPROM storage with CRC for UserData
 - Session token handling (stored in-memory; token returned in JSON and Set-Cookie)
 - Minimal, safe non-blocking sensor handling
*/

#include <EEPROM.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

// --- CONFIG ---
#define EEPROM_SIZE 1024
#define SESSION_TIMEOUT (5 * 60 * 1000UL) // 5 minutes
#define MAX_FAILED_ATTEMPTS 5
#define TOKEN_LENGTH 16
#define EEPROM_INIT_FLAG 0xAA

// Pins
constexpr uint8_t INPUT_PIN_1 = 18;
constexpr uint8_t INPUT_PIN_2 = 19;
constexpr uint8_t INPUT_PIN_3 = 21;
constexpr uint8_t INPUT_PIN_4 = 22;
constexpr uint8_t INPUT_PIN_5 = 23;
constexpr uint8_t BuzzerPin   = 5;

// --- STRUCTS ---
struct PhoneMessage {
  char phoneNumber[15];
  char message[51];
};

struct UserData {
  char username[20];
  char password[20];
  uint8_t isSignupDone;
  uint8_t toggleMode;
  uint8_t reserved[10];
};

struct SessionToken {
  char token[TOKEN_LENGTH + 1];
  unsigned long lastActivity;
  bool isValid;
};

struct EEPROMHeader {
  uint8_t initFlag;
  uint16_t crc;
};

// --- GLOBALS ---
UserData userData;
SessionToken currentSession;
EEPROMHeader eepromHeader;
PhoneMessage phoneMessages[5];
WebServer server(80);

TaskHandle_t webServerTaskHandle = NULL;
TaskHandle_t core1TaskHandle = NULL;

int failedLoginAttempts = 0;
unsigned long lastFailedAttempt = 0;
bool isLockedOut = false;

int previousState1 = HIGH;
int previousState2 = HIGH;
int previousState3 = HIGH;
int previousState4 = HIGH;
int previousState5 = HIGH;

// for sensor triggered buzzer
volatile unsigned long buzzerBeepEndMillis = 0;

// EEPROM addresses
#define EEPROM_HEADER_ADDR 0
#define EEPROM_USER_ADDR (EEPROM_HEADER_ADDR + sizeof(EEPROMHeader))
#define EEPROM_PHONES_ADDR (EEPROM_USER_ADDR + sizeof(UserData))

// --- UTILITIES ---
uint16_t calculateCRC16(uint8_t* data, size_t length) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      if (crc & 1) crc = (crc >> 1) ^ 0xA001;
      else crc = crc >> 1;
    }
  }
  return crc;
}

void generateToken(char* token) {
  const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    token[i] = charset[random(62)];
  }
  token[TOKEN_LENGTH] = 0;
}

bool isValidInput(const char* input, int minLen, int maxLen) {
  int len = strlen(input);
  return (len >= minLen && len <= maxLen);
}

bool isStrongPassword(const char* password) {
  if (!isValidInput(password, 6, 20)) return false;
  bool hasUpper = false, hasLower = false, hasDigit = false;
  for (int i = 0; password[i] != 0; i++) {
    if (isupper(password[i])) hasUpper = true;
    if (islower(password[i])) hasLower = true;
    if (isdigit(password[i])) hasDigit = true;
  }
  return (hasUpper && hasLower && hasDigit);
}

// --- EEPROM handlers ---
void initializeEEPROM() {
  Serial.println("[EEPROM] Initializing");
  for (int i = 0; i < EEPROM_SIZE; i++) EEPROM.write(i, 0);
  eepromHeader.initFlag = EEPROM_INIT_FLAG;
  strcpy(userData.username, "");
  strcpy(userData.password, "");
  userData.isSignupDone = 0;
  userData.toggleMode = 0;
  for (int i = 0; i < 5; i++) {
    strcpy(phoneMessages[i].phoneNumber, "");
    strcpy(phoneMessages[i].message, "");
  }
  uint8_t* dp = (uint8_t*)&userData;
  eepromHeader.crc = calculateCRC16(dp, sizeof(UserData));
  EEPROM.put(EEPROM_HEADER_ADDR, eepromHeader);
  EEPROM.put(EEPROM_USER_ADDR, userData);
  EEPROM.put(EEPROM_PHONES_ADDR, phoneMessages);
  EEPROM.commit();
  Serial.println("[EEPROM] Initialized");
}

bool readFromEEPROM() {
  EEPROM.get(EEPROM_HEADER_ADDR, eepromHeader);
  if (eepromHeader.initFlag != EEPROM_INIT_FLAG) {
    initializeEEPROM();
    return false;
  }
  EEPROM.get(EEPROM_USER_ADDR, userData);
  EEPROM.get(EEPROM_PHONES_ADDR, phoneMessages);
  uint8_t* dp = (uint8_t*)&userData;
  uint16_t calc = calculateCRC16(dp, sizeof(UserData));
  if (calc != eepromHeader.crc) {
    Serial.println("[EEPROM] CRC mismatch - reinitializing");
    initializeEEPROM();
    return false;
  }
  Serial.println("[EEPROM] Read OK");
  return true;
}

bool writeToEEPROM() {
  uint8_t* dp = (uint8_t*)&userData;
  eepromHeader.crc = calculateCRC16(dp, sizeof(UserData));
  EEPROM.put(EEPROM_HEADER_ADDR, eepromHeader);
  EEPROM.put(EEPROM_USER_ADDR, userData);
  EEPROM.put(EEPROM_PHONES_ADDR, phoneMessages);
  if (EEPROM.commit()) {
    Serial.println("[EEPROM] Saved");
    return true;
  }
  Serial.println("[EEPROM] Save failed");
  return false;
}

// --- Session / Auth ---
void createSession() {
  generateToken(currentSession.token);
  currentSession.lastActivity = millis();
  currentSession.isValid = true;
  Serial.print("[SESSION] Created: ");
  Serial.println(currentSession.token);
}

bool validateToken(const char* token) {
  if (!currentSession.isValid) return false;
  if (!token) return false;
  if (strcmp(currentSession.token, token) != 0) return false;
  unsigned long elapsed = millis() - currentSession.lastActivity;
  if (elapsed > SESSION_TIMEOUT) {
    currentSession.isValid = false;
    return false;
  }
  currentSession.lastActivity = millis();
  return true;
}

void invalidateSession() {
  currentSession.isValid = false;
}

bool checkBruteForce() {
  if (isLockedOut) {
    unsigned long lockElapsed = millis() - lastFailedAttempt;
    if (lockElapsed > 60000) {
      isLockedOut = false;
      failedLoginAttempts = 0;
      return false;
    }
    return true;
  }
  return false;
}

void recordFailedAttempt() {
  failedLoginAttempts++;
  lastFailedAttempt = millis();
  if (failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
    isLockedOut = true;
  }
}

void clearFailedAttempts() {
  failedLoginAttempts = 0;
  isLockedOut = false;
}

bool authenticateUser(const char* username, const char* password) {
  if (checkBruteForce()) return false;
  if (!isValidInput(username, 3, 20) || !isValidInput(password, 3, 20)) {
    recordFailedAttempt();
    return false;
  }
  if (strcmp(userData.username, username) != 0) {
    recordFailedAttempt();
    return false;
  }
  if (strcmp(userData.password, password) != 0) {
    recordFailedAttempt();
    return false;
  }
  clearFailedAttempts();
  return true;
}

// --- HTML pages (Signup, Login, Dashboard) ---
String getSignupPage() {
  String html = "<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'>";
  html += "<title>Signup</title><style>body{background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center;font-family:Arial}";
  html += ".form{background:white;padding:40px;border-radius:10px;width:100%;max-width:400px}h2{color:#667eea;text-align:center;margin-bottom:30px}";
  html += ".group{margin:15px 0}label{display:block;font-weight:600;margin-bottom:5px;color:#333}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;font-size:14px}";
  html += "button{width:100%;padding:10px;background:#667eea;color:white;border:none;border-radius:5px;cursor:pointer;font-weight:600;margin-top:20px}";
  html += ".msg{padding:10px;margin:10px 0;border-radius:5px;text-align:center;display:none;font-weight:600}";
  html += ".error{background:#ffebee;color:#d32f2f}.success{background:#e8f5e9;color:#388e3c}";
  html += ".info{text-align:center;margin-top:20px;font-size:14px}a{color:#667eea;cursor:pointer;font-weight:600}";
  html += "</style></head><body><div class=form><h2>Create Account</h2><div id=msg class=msg></div>";
  html += "<form id=f onsubmit='return false'><div class=group><label>Username</label><input id=u required></div>";
  html += "<div class=group><label>Password</label><input id=p type=password required></div>";
  html += "<button onclick=signup()>Sign Up</button></form><div class=info>Have account? <a onclick='location.href=\"/login\"'>Login</a></div>";
  html += "</div><script>";
  html += "function signup(){const u=document.getElementById('u').value,p=document.getElementById('p').value,m=document.getElementById('msg');";
  html += "if(!/[A-Z]/.test(p)||!/[a-z]/.test(p)||!/[0-9]/.test(p)){m.className='msg error';m.textContent='Password needs uppercase, lowercase, digit';m.style.display='block';return false}";
  html += "fetch('/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})})";
  html += ".then(r=>r.json()).then(d=>{if(d.success){m.className='msg success';m.textContent='Account created! Redirecting...';m.style.display='block';setTimeout(()=>location.href='/login',1500)}else{m.className='msg error';m.textContent=d.error||'Error';m.style.display='block'}})};";
  html += "</script></body></html>";
  return html;
}

String getLoginPage() {
  String html = "<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'>";
  html += "<title>Login</title><style>body{background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center;font-family:Arial}";
  html += ".form{background:white;padding:40px;border-radius:10px;width:100%;max-width:400px}h2{color:#667eea;text-align:center;margin-bottom:30px}";
  html += ".group{margin:15px 0}label{display:block;font-weight:600;margin-bottom:5px;color:#333}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;font-size:14px}";
  html += "button{width:100%;padding:10px;background:#667eea;color:white;border:none;border-radius:5px;cursor:pointer;font-weight:600;margin-top:20px}";
  html += ".msg{padding:10px;margin:10px 0;border-radius:5px;text-align:center;display:none;font-weight:600}";
  html += ".error{background:#ffebee;color:#d32f2f}.success{background:#e8f5e9;color:#388e3c}";
  html += ".info{text-align:center;margin-top:20px;font-size:14px}a{color:#667eea;cursor:pointer;font-weight:600}";
  html += "</style></head><body><div class=form><h2>Login</h2><div id=msg class=msg></div>";
  html += "<form id=f onsubmit='return false'><div class=group><label>Username</label><input id=u required></div>";
  html += "<div class=group><label>Password</label><input id=p type=password required></div>";
  html += "<button onclick=login()>Login</button></form><div class=info>No account? <a onclick='location.href=\"/signup\"'>Sign Up</a></div>";
  html += "</div><script>";
  html += "function login(){const u=document.getElementById('u').value,p=document.getElementById('p').value,m=document.getElementById('msg');";
  html += "fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})})";
  html += ".then(r=>r.json()).then(d=>{if(d.success&&d.token){localStorage.setItem('authToken',d.token);m.className='msg success';m.textContent='Login successful!';m.style.display='block';setTimeout(()=>window.location.href='/dashboard',1000)}else{m.className='msg error';m.textContent=d.error||'Login failed';m.style.display='block'}}).catch(e=>{m.className='msg error';m.textContent='Connection error';m.style.display='block'});};";
  html += "</script></body></html>";
  return html;
}

String getDashboardPage() {
  String html = "<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'>";
  html += "<title>Dashboard</title><style>body{font-family:Arial;background:#f0f2f5;margin:0;padding:0}.header{background:#3b5998;color:white;padding:15px;text-align:center}h1{margin:0}";
  html += ".container{width:100%;max-width:900px;margin:0 auto;padding:20px}.card{background:white;border-radius:5px;padding:20px;margin-bottom:20px;box-shadow:0 2px 5px rgba(0,0,0,0.1)}";
  html += ".btn-group{display:flex;gap:10px;margin-bottom:20px}.btn{padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-weight:600}.btn-primary{background:#3b5998;color:white}.btn-danger{background:#d32f2f;color:white}";
  html += ".input-row{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:10px}label{font-weight:600;color:#333;display:block;margin-bottom:5px;font-size:13px}input{width:100%;padding:8px;border:1px solid #ddd;border-radius:5px;font-size:13px}";
  html += ".toggle{display:flex;align-items:center;justify-content:center;gap:20px;margin:20px 0}.footer{text-align:center;color:#666;font-size:11px;margin-top:30px;border-top:1px solid #ddd;padding-top:20px}</style></head><body>";
  html += "<div class=header><h1>Security Dashboard</h1></div><div class=container>";
  html += "<div class=card><div class='btn-group'><button class='btn btn-primary' onclick='save()'>Save</button><button class='btn btn-primary' onclick='reset_()'>Reset</button><button class='btn btn-danger' onclick='logout()'>Logout</button></div></div>";
  html += "<div class=card><h3>Phone Numbers and Messages</h3>";
  for (int i = 0; i < 5; i++) {
    html += "<div class='input-row'><div><label>Phone " + String(i+1) + "</label><input type=text id='phone" + String(i) + "' value='" + String(phoneMessages[i].phoneNumber) + "'></div>";
    html += "<div><label>Message " + String(i+1) + "</label><input type=text id='msg" + String(i) + "' value='" + String(phoneMessages[i].message) + "'></div></div>";
  }
  html += "</div>";
  html += "<div class=card><div class=toggle><span id=ml style='font-weight:600'>Full Features Mode</span><label class=toggle-switch><input type=checkbox id=mode onchange=setMode()>";
  html += "<span class=slider></span></label></div></div>";
  html += "<div class=footer>(C) 2025 Community-Based Industrial IoT</div></div>";
  html += "<script>";
  html += "let t=300; setInterval(()=>{t--; if(t<=0) logout();},1000); document.addEventListener('mousemove',()=>{ const tok = localStorage.getItem('authToken'); if(tok) fetch('/api/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})}); t=300 });";
  html += "function setMode(){ const m=document.getElementById('mode').checked; document.getElementById('ml').textContent=m?'Beep Mode':'Full Features Mode'; fetch('/api/setMode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:m?'beep':'full',token:localStorage.getItem('authToken')})}); }";
  html += "function save(){ const d=[]; for(let i=0;i<5;i++) d.push({phone:document.getElementById('phone'+i).value,msg:document.getElementById('msg'+i).value}); fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phones:d,token:localStorage.getItem('authToken')})}).then(r=>r.json()).then(x=>alert(x.success?'Saved':'Error')); }";
  html += "function reset_(){ if(confirm('Reset all?')) fetch('/api/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:localStorage.getItem('authToken')})}).then(()=>location.reload()); }";
  html += "function logout(){ localStorage.removeItem('authToken'); location.href='/login'; }";
  html += "</script></body></html>";
  return html;
}

// --- ROUTES ---
void setupRoutes() {
  server.on("/", HTTP_GET, []() {
    server.sendHeader("Location", "/login");
    server.send(302);
  });

  server.on("/signup", HTTP_GET, []() { server.send(200, "text/html", getSignupPage()); });
  server.on("/login", HTTP_GET, []() { server.send(200, "text/html", getLoginPage()); });

  server.on("/dashboard", HTTP_GET, []() {
    if (currentSession.isValid) {
      unsigned long elapsed = millis() - currentSession.lastActivity;
      if (elapsed <= SESSION_TIMEOUT) {
        currentSession.lastActivity = millis();
        server.send(200, "text/html", getDashboardPage());
        return;
      }
    }
    server.sendHeader("Location", "/login");
    server.send(302);
  });

  server.on("/api/signup", HTTP_POST, []() {
    if (!server.hasArg("plain")) {
      server.send(400, "application/json", "{\"error\":\"No data\"}");
      return;
    }
    DynamicJsonDocument doc(256);
    deserializeJson(doc, server.arg("plain"));
    const char* user = doc["username"];
    const char* pass = doc["password"];
    if (!user || !pass) { server.send(400, "application/json", "{\"error\":\"Missing\"}"); return; }
    if (userData.isSignupDone) { server.send(400, "application/json", "{\"error\":\"Exists\"}"); return; }
    if (!isValidInput(user, 3, 20)) { server.send(400, "application/json", "{\"error\":\"Invalid\"}"); return; }
    if (!isStrongPassword(pass)) { server.send(400, "application/json", "{\"error\":\"Weak\"}"); return; }

    strncpy(userData.username, user, sizeof(userData.username) - 1); userData.username[sizeof(userData.username)-1] = 0;
    strncpy(userData.password, pass, sizeof(userData.password) - 1); userData.password[sizeof(userData.password)-1] = 0;
    userData.isSignupDone = 1;
    if (writeToEEPROM()) {
      server.send(200, "application/json", "{\"success\":true}");
      Serial.println("[AUTH] Signup OK");
    } else {
      server.send(500, "application/json", "{\"error\":\"Failed\"}");
    }
  });

  server.on("/api/login", HTTP_POST, []() {
    if (!server.hasArg("plain")) { server.send(400, "application/json", "{\"error\":\"No data\"}"); return; }
    DynamicJsonDocument doc(256);
    deserializeJson(doc, server.arg("plain"));
    const char* user = doc["username"];
    const char* pass = doc["password"];
    if (!user || !pass) { server.send(400, "application/json", "{\"error\":\"Missing\"}"); return; }
    if (!userData.isSignupDone) { server.send(401, "application/json", "{\"error\":\"No account\"}"); return; }
    if (authenticateUser(user, pass)) {
      createSession();
      DynamicJsonDocument res(256);
      res["token"] = currentSession.token;
      res["success"] = true;
      String resStr; serializeJson(res, resStr);
      server.sendHeader("Set-Cookie", String("authToken=") + currentSession.token + "; Path=/; Max-Age=300");
      server.send(200, "application/json", resStr);
      Serial.println("[AUTH] Login OK");
    } else {
      server.send(401, "application/json", "{\"error\":\"Invalid\"}");
    }
  });

  server.on("/api/refresh", HTTP_POST, []() {
    if (!server.hasArg("plain")) { server.send(400, "application/json", "{\"error\":\"No data\"}"); return; }
    DynamicJsonDocument doc(256); deserializeJson(doc, server.arg("plain")); const char* tok = doc["token"];
    if (validateToken(tok)) server.send(200, "application/json", "{\"success\":true}");
    else server.send(401, "application/json", "{\"error\":\"Invalid\"}");
  });

  server.on("/api/setMode", HTTP_POST, []() {
    if (!server.hasArg("plain")) { server.send(400, "application/json", "{\"error\":\"No data\"}"); return; }
    DynamicJsonDocument doc(256); deserializeJson(doc, server.arg("plain")); const char* tok = doc["token"]; const char* mode = doc["mode"];
    if (!validateToken(tok)) { server.send(401, "application/json", "{\"error\":\"Invalid\"}"); return; }
    userData.toggleMode = (strcmp(mode, "beep") == 0) ? 1 : 0;
    writeToEEPROM();
    server.send(200, "application/json", "{\"success\":true}");
  });

  server.on("/api/save", HTTP_POST, []() {
    if (!server.hasArg("plain")) { server.send(400, "application/json", "{\"error\":\"No data\"}"); return; }
    DynamicJsonDocument doc(512); deserializeJson(doc, server.arg("plain"));
    const char* tok = doc["token"];
    if (!validateToken(tok)) { server.send(401, "application/json", "{\"error\":\"Invalid\"}"); return; }
    JsonArray phones = doc["phones"];
    for (int i = 0; i < phones.size() && i < 5; i++) {
      const char* p = phones[i]["phone"];
      const char* m = phones[i]["msg"];
      if (p && strlen(p) > 0) { strncpy(phoneMessages[i].phoneNumber, p, sizeof(phoneMessages[i].phoneNumber) - 1); phoneMessages[i].phoneNumber[sizeof(phoneMessages[i].phoneNumber)-1] = 0; } else phoneMessages[i].phoneNumber[0] = 0;
      if (m && strlen(m) > 0) { strncpy(phoneMessages[i].message, m, sizeof(phoneMessages[i].message) - 1); phoneMessages[i].message[sizeof(phoneMessages[i].message)-1] = 0; } else phoneMessages[i].message[0] = 0;
    }
    if (writeToEEPROM()) { server.send(200, "application/json", "{\"success\":true}"); Serial.println("[SAVE] Phones saved"); }
    else server.send(500, "application/json", "{\"error\":\"Failed\"}");
  });

  server.on("/api/reset", HTTP_POST, []() {
    if (!server.hasArg("plain")) { server.send(400, "application/json", "{\"error\":\"No data\"}"); return; }
    DynamicJsonDocument doc(256); deserializeJson(doc, server.arg("plain")); const char* tok = doc["token"];
    if (!validateToken(tok)) { server.send(401, "application/json", "{\"error\":\"Invalid\"}"); return; }
    initializeEEPROM();
    invalidateSession();
    server.send(200, "application/json", "{\"success\":true}");
    Serial.println("[RESET] System reset");
  });
}

// --- FreeRTOS Tasks ---
// Core 0: Web Server task
void webServerTask(void *parameter) {
  Serial.println("[TASK] WebServerTask started on Core 0");
  setupRoutes();
  server.begin();
  Serial.println("[TASK] HTTP server started");
  while (1) {
    server.handleClient();
    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

// Core 1: Sensor and buzzer event handling
void core1Task(void *parameter) {
  Serial.println("[TASK] Core1Task started on Core 1");
  // initialize previous states
  previousState1 = digitalRead(INPUT_PIN_1);
  previousState2 = digitalRead(INPUT_PIN_2);
  previousState3 = digitalRead(INPUT_PIN_3);
  previousState4 = digitalRead(INPUT_PIN_4);
  previousState5 = digitalRead(INPUT_PIN_5);

  while (1) {
    int s;
    s = digitalRead(INPUT_PIN_1);
    if (s != previousState1) {
      previousState1 = s;
      Serial.print("[S1] "); Serial.println(s ? "HIGH" : "LOW");
      if (s == LOW) buzzerBeepEndMillis = millis() + 1000;
    }

    s = digitalRead(INPUT_PIN_2);
    if (s != previousState2) {
      previousState2 = s;
      Serial.print("[S2] "); Serial.println(s ? "HIGH" : "LOW");
      if (s == LOW) buzzerBeepEndMillis = millis() + 1000;
    }

    s = digitalRead(INPUT_PIN_3);
    if (s != previousState3) {
      previousState3 = s;
      Serial.print("[S3] "); Serial.println(s ? "HIGH" : "LOW");
      if (s == LOW) buzzerBeepEndMillis = millis() + 1000;
    }

    s = digitalRead(INPUT_PIN_4);
    if (s != previousState4) {
      previousState4 = s;
      Serial.print("[S4] "); Serial.println(s ? "HIGH" : "LOW");
      if (s == LOW) buzzerBeepEndMillis = millis() + 1000;
    }

    s = digitalRead(INPUT_PIN_5);
    if (s != previousState5) {
      previousState5 = s;
      Serial.print("[S5] "); Serial.println(s ? "HIGH" : "LOW");
      if (s == LOW) buzzerBeepEndMillis = millis() + 1000;
    }

    // drive buzzer for sensor events
    if (millis() < buzzerBeepEndMillis) digitalWrite(BuzzerPin, HIGH);
    else digitalWrite(BuzzerPin, LOW);

    // periodic status
    static unsigned long lastStatus = 0;
    if (millis() - lastStatus > 30000) {
      lastStatus = millis();
      Serial.println("[CORE1] Running... Session valid: " + String(currentSession.isValid ? "Yes" : "No"));
    }

    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
}

// --- Boot beep (runs in setup before tasks created) ---
void bootBeepSequence() {
  Serial.println("[BOOT] Starting boot beep (10 cycles: 1s ON + 100ms OFF) ...");
  pinMode(BuzzerPin, OUTPUT);
  digitalWrite(BuzzerPin, LOW);
  for (int i = 0; i < 10; i++) {
    Serial.printf("[BOOT] cycle %d/10 -> ON\n", i + 1);
    digitalWrite(BuzzerPin, HIGH);
    delay(500); // 1 second ON
    digitalWrite(BuzzerPin, LOW);
    Serial.printf("[BOOT] cycle %d/10 -> OFF\n", i + 1);
    delay(1000);  // 0.1 second OFF
  }
  digitalWrite(BuzzerPin, LOW);
  Serial.println("[BOOT] Boot beep finished.");
}

// --- SETUP & LOOP ---
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== ESP32 SECURITY SYSTEM ===");

  if (!EEPROM.begin(EEPROM_SIZE)) {
    Serial.println("[ERROR] EEPROM.begin failed");
  }

  if (!readFromEEPROM()) {
    initializeEEPROM();
  }

  // configure sensor pins (inputs) and buzzer
  pinMode(INPUT_PIN_1, INPUT_PULLUP);
  pinMode(INPUT_PIN_2, INPUT_PULLUP);
  pinMode(INPUT_PIN_3, INPUT_PULLUP);
  pinMode(INPUT_PIN_4, INPUT_PULLUP);
  pinMode(INPUT_PIN_5, INPUT_PULLUP);
  pinMode(BuzzerPin, OUTPUT);
  digitalWrite(BuzzerPin, LOW);

  // 1) Run boot beep sequence BEFORE any FreeRTOS tasks created
  bootBeepSequence();

  // 2) Now start WiFi AP (after boot)
  Serial.println("[WiFi] Starting AP...");
  WiFi.mode(WIFI_AP);
  WiFi.softAP("SecuritySystem", "password123");
  Serial.print("[WiFi] IP: ");
  Serial.println(WiFi.softAPIP());
  Serial.println("Access: http://192.168.4.1/signup");

  // 3) Now create tasks
  Serial.println("[FreeRTOS] Creating tasks...");
  xTaskCreatePinnedToCore(webServerTask, "WebServerTask", 10000, NULL, 1, &webServerTaskHandle, 0);
  xTaskCreatePinnedToCore(core1Task, "Core1Task", 8000, NULL, 1, &core1TaskHandle, 1);

  // initialize session
  currentSession.isValid = false;
  randomSeed(analogRead(36) + millis());
}

void loop() {
  // minimal main loop; tasks handle things
  static unsigned long lastLog = 0;
  if (millis() - lastLog > 60000) {
    lastLog = millis();
    Serial.println("[MAIN] alive...");
  }
  vTaskDelay(1000 / portTICK_PERIOD_MS);
}
