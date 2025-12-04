#include "YaraScanner.h"
#include <QFile>
#include <QRegularExpression>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QEventLoop>

YaraScanner::YaraScanner(QObject *parent)
    : QObject(parent)
{
}

YaraScanner::~YaraScanner()
{
}

bool YaraScanner::scanFile(const QString &filePath, const QString &rulesPath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit scanError("Cannot open file: " + filePath);
        return false;
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    return scanBuffer(data, rulesPath);
}

bool YaraScanner::scanBuffer(const QByteArray &data, const QString &rulesPath)
{
    QFile rulesFile(rulesPath);
    if (!rulesFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        emit scanError("Cannot open rules file: " + rulesPath);
        return false;
    }
    
    QString rulesContent = QString::fromUtf8(rulesFile.readAll());
    rulesFile.close();
    
    return scanWithRules(data, rulesContent);
}

bool YaraScanner::scanWithRules(const QByteArray &data, const QString &rulesContent)
{
    emit scanProgress(0, "Parsing rules...");
    
    // Use simple pattern matching (works without libyara dependency)
    QList<YaraMatch> matches = simplePatternScan(data, rulesContent);
    
    emit scanProgress(100, "Scan complete");
    emit scanComplete(matches);
    
    return true;
}

QList<YaraMatch> YaraScanner::simplePatternScan(const QByteArray &data, const QString &rulesContent)
{
    QList<YaraMatch> results;
    
    // Parse YARA-like rules
    // Simple format: rule name { strings: $s1 = "pattern" condition: $s1 }
    QRegularExpression ruleRegex(
        R"(rule\s+(\w+)(?:\s*:\s*(\w+(?:\s+\w+)*))?\s*\{([^}]+)\})",
        QRegularExpression::DotMatchesEverythingOption
    );
    
    QRegularExpressionMatchIterator ruleIt = ruleRegex.globalMatch(rulesContent);
    int ruleCount = 0;
    
    while (ruleIt.hasNext()) {
        QRegularExpressionMatch ruleMatch = ruleIt.next();
        QString ruleName = ruleMatch.captured(1);
        QString tags = ruleMatch.captured(2);
        QString ruleBody = ruleMatch.captured(3);
        
        ruleCount++;
        emit scanProgress(10 + (ruleCount * 5) % 80, "Scanning: " + ruleName);
        
        YaraMatch yaraMatch;
        yaraMatch.ruleName = ruleName;
        yaraMatch.tags = tags.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        
        // Parse strings section
        QRegularExpression stringRegex(R"(\$(\w+)\s*=\s*(?:\"([^\"]+)\"|{([^}]+)}))");
        QRegularExpressionMatchIterator stringIt = stringRegex.globalMatch(ruleBody);
        
        bool hasMatch = false;
        
        while (stringIt.hasNext()) {
            QRegularExpressionMatch stringMatch = stringIt.next();
            QString varName = stringMatch.captured(1);
            QString asciiPattern = stringMatch.captured(2);
            QString hexPattern = stringMatch.captured(3);
            
            QByteArray pattern;
            if (!asciiPattern.isEmpty()) {
                pattern = asciiPattern.toUtf8();
            } else if (!hexPattern.isEmpty()) {
                // Parse hex pattern like "4D 5A 90"
                hexPattern.remove(QRegularExpression("\\s+"));
                pattern = QByteArray::fromHex(hexPattern.toUtf8());
            }
            
            if (!pattern.isEmpty()) {
                // Search for pattern in data
                int pos = 0;
                while ((pos = data.indexOf(pattern, pos)) != -1) {
                    yaraMatch.matches.append(QPair<offset_t, size_t>(pos, pattern.size()));
                    hasMatch = true;
                    pos += pattern.size();
                }
            }
        }
        
        // Parse metadata
        QRegularExpression metaRegex(R"((\w+)\s*=\s*\"([^\"]+)\")");
        QRegularExpressionMatchIterator metaIt = metaRegex.globalMatch(ruleBody);
        while (metaIt.hasNext()) {
            QRegularExpressionMatch metaMatch = metaIt.next();
            yaraMatch.metadata[metaMatch.captured(1)] = metaMatch.captured(2);
        }
        
        if (hasMatch) {
            results.append(yaraMatch);
        }
    }
    
    return results;
}

bool YaraScanner::compileRules(const QString &rulesPath, QString &errorMsg)
{
    QFile file(rulesPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        errorMsg = "Cannot open rules file";
        return false;
    }
    
    QString content = QString::fromUtf8(file.readAll());
    return validateRule(content, errorMsg);
}

bool YaraScanner::validateRule(const QString &ruleContent, QString &errorMsg)
{
    // Basic syntax validation
    QRegularExpression ruleRegex(R"(rule\s+\w+\s*(?::\s*\w+(?:\s+\w+)*)?\s*\{)");
    
    if (!ruleRegex.match(ruleContent).hasMatch()) {
        errorMsg = "Invalid rule syntax: missing 'rule' declaration";
        return false;
    }
    
    int braceCount = 0;
    for (QChar c : ruleContent) {
        if (c == '{') braceCount++;
        if (c == '}') braceCount--;
    }
    
    if (braceCount != 0) {
        errorMsg = "Mismatched braces in rule";
        return false;
    }
    
    return true;
}

QStringList YaraScanner::getAvailableRuleSets()
{
    return QStringList {
        "malware_index",      // Common malware signatures
        "packer_compiler",    // Packer and compiler detection
        "capabilities",       // Capability detection
        "crypto",             // Cryptographic signatures
        "cve_rules",          // CVE-specific rules
        "webshells",          // Web shell detection
        "ransomware"          // Ransomware families
    };
}

bool YaraScanner::downloadRuleSet(const QString &name, const QString &savePath)
{
    // URLs for popular YARA rule repositories
    QMap<QString, QString> ruleUrls;
    ruleUrls["malware_index"] = "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar";
    ruleUrls["packer_compiler"] = "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer.yar";
    ruleUrls["capabilities"] = "https://raw.githubusercontent.com/Yara-Rules/rules/master/capabilities/capabilities.yar";
    ruleUrls["crypto"] = "https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar";
    
    if (!ruleUrls.contains(name)) {
        emit scanError("Unknown rule set: " + name);
        return false;
    }
    
    QNetworkAccessManager manager;
    QNetworkReply *reply = manager.get(QNetworkRequest(QUrl(ruleUrls[name])));
    
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    
    if (reply->error() != QNetworkReply::NoError) {
        emit scanError("Download failed: " + reply->errorString());
        reply->deleteLater();
        return false;
    }
    
    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly)) {
        emit scanError("Cannot save rules to: " + savePath);
        reply->deleteLater();
        return false;
    }
    
    file.write(reply->readAll());
    file.close();
    reply->deleteLater();
    
    return true;
}

QString YaraScanner::getBuiltInRules()
{
    return R"(
rule Suspicious_PE_Header {
    meta:
        description = "Detects suspicious PE characteristics"
        author = "PE-bear AI"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule Packed_UPX {
    meta:
        description = "UPX packed executable"
        author = "PE-bear AI"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        any of them
}

rule Packed_ASPack {
    meta:
        description = "ASPack packed executable"
    strings:
        $aspack = ".aspack"
        $adata = ".adata"
    condition:
        any of them
}

rule Packed_Themida {
    meta:
        description = "Themida/WinLicense protected"
    strings:
        $s1 = ".themida"
        $s2 = "Themida"
        $s3 = ".winlice"
    condition:
        any of them
}

rule Packed_VMProtect {
    meta:
        description = "VMProtect protected"
    strings:
        $s1 = ".vmp0"
        $s2 = ".vmp1"
        $s3 = "VMProtect"
    condition:
        any of them
}

rule Suspicious_Imports {
    meta:
        description = "Suspicious API imports for code injection"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "NtUnmapViewOfSection"
        $a5 = "QueueUserAPC"
    condition:
        3 of them
}

rule Keylogger_Indicators {
    meta:
        description = "Potential keylogger"
    strings:
        $a1 = "GetAsyncKeyState"
        $a2 = "GetKeyState"
        $a3 = "SetWindowsHookEx"
        $a4 = "GetKeyboardState"
    condition:
        2 of them
}

rule Network_Communication {
    meta:
        description = "Network communication capability"
    strings:
        $ws1 = "WSAStartup"
        $ws2 = "socket"
        $ws3 = "connect"
        $ws4 = "send"
        $ws5 = "recv"
        $http1 = "InternetOpen"
        $http2 = "HttpOpenRequest"
        $http3 = "URLDownloadToFile"
    condition:
        (3 of ($ws*)) or (2 of ($http*))
}

rule Crypto_Ransomware {
    meta:
        description = "Potential ransomware indicators"
    strings:
        $c1 = "CryptEncrypt"
        $c2 = "CryptGenKey"
        $c3 = "CryptAcquireContext"
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = "YOUR FILES"
        $ext4 = "DECRYPT"
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        (2 of ($c*)) and (1 of ($ext*) or $btc)
}

rule AntiDebug_Techniques {
    meta:
        description = "Anti-debugging techniques detected"
    strings:
        $a1 = "IsDebuggerPresent"
        $a2 = "CheckRemoteDebuggerPresent"
        $a3 = "NtQueryInformationProcess"
        $a4 = "OutputDebugString"
        $a5 = "GetTickCount"
        $a6 = "QueryPerformanceCounter"
    condition:
        3 of them
}

rule Persistence_Registry {
    meta:
        description = "Registry persistence mechanism"
    strings:
        $r1 = "CurrentVersion\\Run"
        $r2 = "CurrentVersion\\RunOnce"
        $r3 = "RegSetValueEx"
        $r4 = "RegCreateKeyEx"
    condition:
        ($r1 or $r2) and ($r3 or $r4)
}

rule Shellcode_Patterns {
    meta:
        description = "Common shellcode patterns"
    strings:
        $sc1 = { 31 c0 50 68 2f 2f 73 68 }  // Linux shellcode
        $sc2 = { fc e8 ?? ?? ?? ?? }          // Windows call pop
        $sc3 = { 60 89 e5 31 c0 64 8b 50 30 } // PEB access
        $sc4 = { e8 00 00 00 00 }             // call $+5
    condition:
        any of them
}
)";
}
