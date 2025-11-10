/*
 * ESP32 SECURE AUTHENTICATION SYSTEM
 * FreeRTOS Dual-Core Implementation
 * Core 0: Web Server + Authentication
 * Core 1: Free for custom tasks (Sensors, Relays, etc.)
 */

#include <EEPROM.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define EEPROM_SIZE 1024
#define SESSION_TIMEOUT 10000
#define MAX_FAILED_ATTEMPTS 5
#define TOKEN_LENGTH 16
#define EEPROM_INIT_FLAG 0xAA

// Task Handles
TaskHandle_t webServerTaskHandle = NULL;
TaskHandle_t core1TaskHandle = NULL;

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

UserData userData;
SessionToken currentSession;
EEPROMHeader eepromHeader;
PhoneMessage phoneMessages[5];
WebServer server(80);

int failedLoginAttempts = 0;
unsigned long lastFailedAttempt = 0;
bool isLockedOut = false;

// Flags for Core 1 communication
volatile bool sensorTriggered = false;
volatile bool callSequenceActive = false;
volatile int activePhoneIndex = 0;

#define EEPROM_HEADER_ADDR 0
#define EEPROM_USER_ADDR (EEPROM_HEADER_ADDR + sizeof(EEPROMHeader))
#define EEPROM_PHONES_ADDR (EEPROM_USER_ADDR + sizeof(UserData))

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

bool isValidPhone(const char* phone) {
    int len = strlen(phone);
    return (len == 0 || (len >= 10 && len <= 15));
}

void initializeEEPROM() {
    Serial.println("[EEPROM] Initializing");
    for (int i = 0; i < EEPROM_SIZE; i++) {
        EEPROM.write(i, 0);
    }
    eepromHeader.initFlag = EEPROM_INIT_FLAG;
    strcpy(userData.username, "");
    strcpy(userData.password, "");
    userData.isSignupDone = 0;
    userData.toggleMode = 0;
    
    for (int i = 0; i < 5; i++) {
        strcpy(phoneMessages[i].phoneNumber, "");
        strcpy(phoneMessages[i].message, "");
    }
    
    uint8_t* dataPtr = (uint8_t*)&userData;
    eepromHeader.crc = calculateCRC16(dataPtr, sizeof(UserData));
    
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
    
    uint8_t* dataPtr = (uint8_t*)&userData;
    uint16_t calculatedCRC = calculateCRC16(dataPtr, sizeof(UserData));
    
    if (calculatedCRC != eepromHeader.crc) {
        return false;
    }
    
    Serial.println("[EEPROM] Read OK");
    return true;
}

bool writeToEEPROM() {
    uint8_t* dataPtr = (uint8_t*)&userData;
    eepromHeader.crc = calculateCRC16(dataPtr, sizeof(UserData));
    
    EEPROM.put(EEPROM_HEADER_ADDR, eepromHeader);
    EEPROM.put(EEPROM_USER_ADDR, userData);
    EEPROM.put(EEPROM_PHONES_ADDR, phoneMessages);
    
    if (EEPROM.commit()) {
        Serial.println("[EEPROM] Saved");
        return true;
    }
    return false;
}

void createSession() {
    generateToken(currentSession.token);
    currentSession.lastActivity = millis();
    currentSession.isValid = true;
    Serial.print("[SESSION] Created: ");
    Serial.println(currentSession.token);
}

bool validateToken(const char* token) {
    if (!currentSession.isValid) return false;
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
    html += ".then(r=>r.json()).then(d=>{if(d.success){m.className='msg success';m.textContent='Account created! Redirecting...';m.style.display='block';";
    html += "setTimeout(()=>location.href='/login',1500)}else{m.className='msg error';m.textContent=d.error||'Error';m.style.display='block'}})};";
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
    html += ".then(r=>r.json()).then(d=>{if(d.success&&d.token){m.className='msg success';m.textContent='Login successful!';m.style.display='block';";
    html += "setTimeout(()=>window.location.href='/dashboard',1000)}else{m.className='msg error';m.textContent=d.error||'Login failed';m.style.display='block'}})";
    html += ".catch(e=>{m.className='msg error';m.textContent='Connection error';m.style.display='block'});};";
    html += "</script></body></html>";
    return html;
}

String getDashboardPage() {
    String html = "<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'>";
    html += "<title>Dashboard</title><style>";
    html += "body{font-family:Arial;background:#f0f2f5;margin:0;padding:0}";
    html += ".header{background:#3b5998;color:white;padding:15px;text-align:center}h1{margin:0}";
    html += ".container{width:100%;max-width:900px;margin:0 auto;padding:20px}";
    html += ".card{background:white;border-radius:5px;padding:20px;margin-bottom:20px;box-shadow:0 2px 5px rgba(0,0,0,0.1)}";
    html += ".btn-group{display:flex;gap:10px;margin-bottom:20px}.btn{padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-weight:600}";
    html += ".btn-primary{background:#3b5998;color:white}.btn-danger{background:#d32f2f;color:white}";
    html += ".input-row{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:10px}";
    html += "label{font-weight:600;color:#333;display:block;margin-bottom:5px;font-size:13px}";
    html += "input{width:100%;padding:8px;border:1px solid #ddd;border-radius:5px;font-size:13px}";
    html += ".toggle{display:flex;align-items:center;justify-content:center;gap:20px;margin:20px 0}";
    html += ".toggle-switch{position:relative;width:60px;height:30px}";
    html += ".toggle-switch input{opacity:0;width:0;height:0}";
    html += ".slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#ccc;border-radius:30px;transition:0.4s}";
    html += ".slider:before{position:absolute;content:'';height:22px;width:22px;border-radius:50%;left:4px;top:4px;background:white;transition:0.4s}";
    html += "input:checked+.slider{background:#3b5998}input:checked+.slider:before{transform:translateX(30px)}";
    html += ".footer{text-align:center;color:#666;font-size:11px;margin-top:30px;border-top:1px solid #ddd;padding-top:20px}";
    html += "@media(max-width:600px){.input-row{grid-template-columns:1fr}}";
    html += "</style></head><body>";
    html += "<div class=header><h1>Security Dashboard</h1></div>";
    html += "<div class=container>";
    html += "<div class=card>";
    html += "<div class=btn-group>";
    html += "<button class=btn class=btn-primary onclick=save()>Save</button>";
    html += "<button class=btn class=btn-primary onclick=reset()>Reset</button>";
    html += "<button class=btn class=btn-danger onclick=logout()>Logout</button>";
    html += "</div></div>";
    
    html += "<div class=card>";
    html += "<h3>Phone Numbers and Messages</h3>";
    for (int i = 0; i < 5; i++) {
        html += "<div class=input-row>";
        html += "<div><label>Phone Number " + String(i+1) + "</label>";
        html += "<input type=text id=phone" + String(i) + " value='" + String(phoneMessages[i].phoneNumber) + "'></div>";
        html += "<div><label>Message " + String(i+1) + "</label>";
        html += "<input type=text id=msg" + String(i) + " value='" + String(phoneMessages[i].message) + "'></div>";
        html += "</div>";
    }
    html += "</div>";
    
    html += "<div class=card>";
    html += "<div class=toggle>";
    html += "<span id=ml style='font-weight:600'>Full Features Mode</span>";
    html += "<label class=toggle-switch>";
    html += "<input type=checkbox id=mode onchange=setMode()";
    if (userData.toggleMode) html += " checked";
    html += ">";
    html += "<span class=slider></span></label></div></div>";
    
    html += "<div class=footer>(C) 2025 Community-Based Industrial IoT - Dual Core System</div>";
    html += "</div>";
    
    html += "<script>";
    html += "let t=10;";
    html += "setInterval(()=>{t--;if(t<=0)logout()},1000);";
    html += "document.addEventListener('mousemove',()=>{";
    html += "fetch('/api/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:localStorage.getItem('authToken')})});";
    html += "t=10});";
    html += "function setMode(){";
    html += "const m=document.getElementById('mode').checked;";
    html += "document.getElementById('ml').textContent=m?'Beep Mode':'Full Features Mode';";
    html += "fetch('/api/setMode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:m?'beep':'full',token:localStorage.getItem('authToken')})});";
    html += "}";
    html += "function save(){";
    html += "const d=[];for(let i=0;i<5;i++)d.push({phone:document.getElementById('phone'+i).value,msg:document.getElementById('msg'+i).value});";
    html += "fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phones:d,token:localStorage.getItem('authToken')})})";
    html += ".then(r=>r.json()).then(r=>{alert(r.success?'Saved':'Error')});";
    html += "}";
    html += "function reset(){if(confirm('Reset all?')){";
    html += "fetch('/api/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:localStorage.getItem('authToken')})})";
    html += ".then(()=>{location.reload()});}}";
    html += "function logout(){localStorage.removeItem('authToken');location.href='/login'}";
    html += "</script></body></html>";
    return html;
}

void setupRoutes() {
    server.on("/", HTTP_GET, []() {
        server.sendHeader("Location", "/login");
        server.send(302);
    });
    
    server.on("/signup", HTTP_GET, []() {
        server.send(200, "text/html", getSignupPage());
    });
    
    server.on("/login", HTTP_GET, []() {
        server.send(200, "text/html", getLoginPage());
    });
    
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
        
        if (!user || !pass) {
            server.send(400, "application/json", "{\"error\":\"Missing\"}");
            return;
        }
        if (userData.isSignupDone) {
            server.send(400, "application/json", "{\"error\":\"Exists\"}");
            return;
        }
        if (!isValidInput(user, 3, 20)) {
            server.send(400, "application/json", "{\"error\":\"Invalid\"}");
            return;
        }
        if (!isStrongPassword(pass)) {
            server.send(400, "application/json", "{\"error\":\"Weak\"}");
            return;
        }
        strcpy(userData.username, user);
        strcpy(userData.password, pass);
        userData.isSignupDone = 1;
        if (writeToEEPROM()) {
            server.send(200, "application/json", "{\"success\":true}");
            Serial.println("[AUTH] Signup OK");
        } else {
            server.send(500, "application/json", "{\"error\":\"Failed\"}");
        }
    });
    
    server.on("/api/login", HTTP_POST, []() {
        if (!server.hasArg("plain")) {
            server.send(400, "application/json", "{\"error\":\"No data\"}");
            return;
        }
        DynamicJsonDocument doc(256);
        deserializeJson(doc, server.arg("plain"));
        const char* user = doc["username"];
        const char* pass = doc["password"];
        
        if (!user || !pass) {
            server.send(400, "application/json", "{\"error\":\"Missing\"}");
            return;
        }
        if (!userData.isSignupDone) {
            server.send(401, "application/json", "{\"error\":\"No account\"}");
            return;
        }
        if (authenticateUser(user, pass)) {
            createSession();
            DynamicJsonDocument res(256);
            res["token"] = currentSession.token;
            res["success"] = true;
            String resStr;
            serializeJson(res, resStr);
            server.sendHeader("Set-Cookie", String("authToken=") + currentSession.token + "; Path=/; Max-Age=10");
            server.send(200, "application/json", resStr);
            Serial.println("[AUTH] Login OK");
        } else {
            server.send(401, "application/json", "{\"error\":\"Invalid\"}");
        }
    });
    
    server.on("/api/refresh", HTTP_POST, []() {
        if (!server.hasArg("plain")) return;
        DynamicJsonDocument doc(256);
        deserializeJson(doc, server.arg("plain"));
        const char* tok = doc["token"];
        if (validateToken(tok)) {
            server.send(200, "application/json", "{\"success\":true}");
        } else {
            server.send(401, "application/json", "{\"error\":\"Invalid\"}");
        }
    });
    
    server.on("/api/setMode", HTTP_POST, []() {
        if (!server.hasArg("plain")) return;
        DynamicJsonDocument doc(256);
        deserializeJson(doc, server.arg("plain"));
        const char* tok = doc["token"];
        const char* mode = doc["mode"];
        
        if (!validateToken(tok)) {
            server.send(401, "application/json", "{\"error\":\"Invalid\"}");
            return;
        }
        userData.toggleMode = (strcmp(mode, "beep") == 0) ? 1 : 0;
        writeToEEPROM();
        Serial.println(userData.toggleMode ? "[MODE] Beep Mode" : "[MODE] Full Features");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/api/save", HTTP_POST, []() {
        if (!server.hasArg("plain")) return;
        DynamicJsonDocument doc(512);
        deserializeJson(doc, server.arg("plain"));
        const char* tok = doc["token"];
        
        if (!validateToken(tok)) {
            server.send(401, "application/json", "{\"error\":\"Invalid\"}");
            return;
        }
        
        JsonArray phones = doc["phones"];
        for (int i = 0; i < phones.size() && i < 5; i++) {
            const char* p = phones[i]["phone"];
            const char* m = phones[i]["msg"];
            strcpy(phoneMessages[i].phoneNumber, (p && strlen(p) > 0) ? p : "");
            strcpy(phoneMessages[i].message, (m && strlen(m) > 0) ? m : "");
        }
        
        if (writeToEEPROM()) {
            server.send(200, "application/json", "{\"success\":true}");
            Serial.println("[SAVE] Phones saved");
        } else {
            server.send(500, "application/json", "{\"error\":\"Failed\"}");
        }
    });
    
    server.on("/api/reset", HTTP_POST, []() {
        if (!server.hasArg("plain")) return;
        DynamicJsonDocument doc(256);
        deserializeJson(doc, server.arg("plain"));
        const char* tok = doc["token"];
        
        if (!validateToken(tok)) {
            server.send(401, "application/json", "{\"error\":\"Invalid\"}");
            return;
        }
        
        initializeEEPROM();
        invalidateSession();
        server.send(200, "application/json", "{\"success\":true}");
        Serial.println("[RESET] System reset");
    });
}

// ==================== FREERTOS TASKS ====================

// CORE 0: Web Server Task
void webServerTask(void *parameter) {
    Serial.println("[TASK] Web Server started on Core 0");
    setupRoutes();
    server.begin();
    
    while (1) {
        server.handleClient();
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

// CORE 1: Custom Task (Available for Sensors, Relays, etc.)
void core1Task(void *parameter) {
    Serial.println("[TASK] Core 1 Task started - Ready for custom operations");
    
    while (1) {
        // This core is free for your custom code
        // Example: Sensor reading, relay control, call sequences, etc.
        
        if (sensorTriggered) {
            Serial.println("[CORE1] Sensor triggered!");
            // Add your sensor handling code here
            sensorTriggered = false;
        }
        
        if (callSequenceActive) {
            Serial.println("[CORE1] Call sequence active for phone: " + String(activePhoneIndex));
            // Add your call sequence code here
            callSequenceActive = false;
        }
        
        // Print status every 30 seconds
        static unsigned long lastStatus = 0;
        if (millis() - lastStatus > 30000) {
            lastStatus = millis();
            Serial.println("[CORE1] Running... Session valid: " + String(currentSession.isValid ? "Yes" : "No"));
        }
        
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

// ==================== SETUP ====================

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n\n=========================================");
    Serial.println("ESP32 SECURITY SYSTEM - DUAL CORE");
    Serial.println("=========================================");
    Serial.println("Core 0: Web Server + Authentication");
    Serial.println("Core 1: Free for Custom Tasks");
    Serial.println("=========================================");
    
    if (!EEPROM.begin(EEPROM_SIZE)) {
        Serial.println("[ERROR] EEPROM failed");
        return;
    }
    
    if (!readFromEEPROM()) {
        initializeEEPROM();
    }
    
    WiFi.mode(WIFI_AP);
    WiFi.softAP("SecuritySystem", "password123");
    Serial.print("[WiFi] IP: ");
    Serial.println(WiFi.softAPIP());
    Serial.println("[WiFi] SSID: SecuritySystem");
    Serial.println("[WiFi] Password: password123");
    
    currentSession.isValid = false;
    randomSeed(analogRead(36) + millis());
    
    Serial.println("\n[FreeRTOS] Creating tasks...");
    
    // Create Web Server Task on Core 0
    xTaskCreatePinnedToCore(
        webServerTask,           // Task function
        "WebServerTask",         // Task name
        10000,                   // Stack size
        NULL,                    // Parameters
        1,                       // Priority
        &webServerTaskHandle,    // Task handle
        0                        // Core 0
    );
    
    // Create Core 1 Task on Core 1 (Available for custom code)
    xTaskCreatePinnedToCore(
        core1Task,               // Task function
        "Core1Task",             // Task name
        8000,                    // Stack size
        NULL,                    // Parameters
        1,                       // Priority
        &core1TaskHandle,        // Task handle
        1                        // Core 1
    );
    
    Serial.println("[FreeRTOS] Tasks created successfully");
    Serial.println("=========================================\n");
    Serial.println("Access: http://192.168.4.1/signup");
    Serial.println("=========================================\n");
}

// ==================== MAIN LOOP ====================

void loop() {
    // Main loop on Core 0 - minimal operations
    // Most operations handled in FreeRTOS tasks
    
    // Check session timeout
    if (currentSession.isValid) {
        unsigned long elapsed = millis() - currentSession.lastActivity;
        if (elapsed > SESSION_TIMEOUT) {
            invalidateSession();
        }
    }
    
    // Print system status every 60 seconds
    static unsigned long lastLog = 0;
    if (millis() - lastLog > 60000) {
        lastLog = millis();
        Serial.println("\n[SYSTEM] Status Report:");
        Serial.print("  Session: ");
        Serial.println(currentSession.isValid ? "ACTIVE" : "INACTIVE");
        Serial.print("  User: ");
        Serial.println(userData.isSignupDone ? userData.username : "None");
        Serial.print("  Mode: ");
        Serial.println(userData.toggleMode ? "BEEP MODE" : "FULL FEATURES");
        Serial.print("  Core 0 Task: ");
        Serial.println(webServerTaskHandle ? "RUNNING" : "STOPPED");
        Serial.print("  Core 1 Task: ");
        Serial.println(core1TaskHandle ? "RUNNING" : "STOPPED");
        Serial.println();
    }
    
    delay(1000);
}