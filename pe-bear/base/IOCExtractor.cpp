#include "IOCExtractor.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

QRegularExpression IOCExtractor::urlRegex;
QRegularExpression IOCExtractor::ipv4Regex;
QRegularExpression IOCExtractor::ipv6Regex;
QRegularExpression IOCExtractor::domainRegex;
QRegularExpression IOCExtractor::emailRegex;
QRegularExpression IOCExtractor::filePathRegex;
QRegularExpression IOCExtractor::registryRegex;
QRegularExpression IOCExtractor::md5Regex;
QRegularExpression IOCExtractor::sha1Regex;
QRegularExpression IOCExtractor::sha256Regex;
QRegularExpression IOCExtractor::bitcoinRegex;

IOCExtractor::IOCExtractor(QObject *parent)
    : QObject(parent), regexesInitialized(false)
{
    initRegexes();
    loadKnownMalicious();
}

IOCExtractor::~IOCExtractor()
{
}

void IOCExtractor::initRegexes()
{
    if (regexesInitialized) return;
    
    urlRegex = QRegularExpression(
        R"((https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|])",
        QRegularExpression::CaseInsensitiveOption
    );
    
    ipv4Regex = QRegularExpression(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"
    );
    
    ipv6Regex = QRegularExpression(
        R"((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})"
    );
    
    domainRegex = QRegularExpression(
        R"(\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|int|io|co|info|biz|xyz|top|online|site|club|ru|cn|tk|pw|cc|ws|su|onion)\b)",
        QRegularExpression::CaseInsensitiveOption
    );
    
    emailRegex = QRegularExpression(
        R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"
    );
    
    filePathRegex = QRegularExpression(
        R"((?:[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)|(?:/(?:[^/\0]+/)*[^/\0]+))"
    );
    
    registryRegex = QRegularExpression(
        R"((?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\[^\s\x00]+)",
        QRegularExpression::CaseInsensitiveOption
    );
    
    md5Regex = QRegularExpression(R"(\b[a-fA-F0-9]{32}\b)");
    sha1Regex = QRegularExpression(R"(\b[a-fA-F0-9]{40}\b)");
    sha256Regex = QRegularExpression(R"(\b[a-fA-F0-9]{64}\b)");
    
    bitcoinRegex = QRegularExpression(R"(\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b)");
    
    regexesInitialized = true;
}

void IOCExtractor::loadKnownMalicious()
{
    // Common malicious/suspicious TLDs and domains
    knownMaliciousDomains.insert("malware.com");
    knownMaliciousDomains.insert("evil.com");
    // In real implementation, load from threat intel feed
}

QList<IOC> IOCExtractor::extractAll(const QStringList &strings)
{
    QList<IOC> allIOCs;
    
    allIOCs.append(extractURLs(strings));
    allIOCs.append(extractIPs(strings));
    allIOCs.append(extractDomains(strings));
    allIOCs.append(extractEmails(strings));
    allIOCs.append(extractFilePaths(strings));
    allIOCs.append(extractRegistryKeys(strings));
    allIOCs.append(extractHashes(strings));
    allIOCs.append(extractBitcoinAddresses(strings));
    
    // Remove duplicates
    QSet<QString> seen;
    QList<IOC> unique;
    for (const IOC &ioc : allIOCs) {
        QString key = QString::number(ioc.type) + ":" + ioc.value;
        if (!seen.contains(key)) {
            seen.insert(key);
            unique.append(ioc);
        }
    }
    
    emit extractionComplete(unique);
    return unique;
}

QList<IOC> IOCExtractor::extractFromBinary(const QByteArray &data)
{
    // Extract ASCII strings from binary
    QStringList strings;
    QString current;
    
    for (int i = 0; i < data.size(); i++) {
        char c = data[i];
        if (c >= 0x20 && c < 0x7F) {
            current += c;
        } else {
            if (current.length() >= 4) {
                strings.append(current);
            }
            current.clear();
        }
    }
    if (current.length() >= 4) {
        strings.append(current);
    }
    
    return extractAll(strings);
}

QList<IOC> IOCExtractor::extractURLs(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        QRegularExpressionMatchIterator it = urlRegex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::URL;
            ioc.value = match.captured(0);
            ioc.defanged = defang(ioc.value, IOC::URL);
            ioc.isSuspicious = ioc.value.contains(".onion") || 
                              ioc.value.contains(".tk") ||
                              ioc.value.contains(".pw") ||
                              ioc.value.contains("pastebin");
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractIPs(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        // IPv4
        QRegularExpressionMatchIterator it = ipv4Regex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::IP_ADDRESS;
            ioc.value = match.captured(0);
            ioc.defanged = defang(ioc.value, IOC::IP_ADDRESS);
            ioc.isSuspicious = !isPrivateIP(ioc.value) && !isLocalhost(ioc.value);
            iocs.append(ioc);
        }
        
        // IPv6
        it = ipv6Regex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::IP_ADDRESS;
            ioc.value = match.captured(0);
            ioc.defanged = defang(ioc.value, IOC::IP_ADDRESS);
            ioc.isSuspicious = true;
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractDomains(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        QRegularExpressionMatchIterator it = domainRegex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::DOMAIN;
            ioc.value = match.captured(0).toLower();
            ioc.defanged = defang(ioc.value, IOC::DOMAIN);
            ioc.isSuspicious = ioc.value.endsWith(".onion") ||
                              ioc.value.endsWith(".tk") ||
                              ioc.value.endsWith(".pw") ||
                              ioc.value.endsWith(".su") ||
                              knownMaliciousDomains.contains(ioc.value);
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractEmails(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        QRegularExpressionMatchIterator it = emailRegex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::EMAIL;
            ioc.value = match.captured(0).toLower();
            ioc.defanged = defang(ioc.value, IOC::EMAIL);
            ioc.isSuspicious = ioc.value.contains("protonmail") ||
                              ioc.value.contains("tutanota") ||
                              ioc.value.contains("cock.li");
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractFilePaths(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        QRegularExpressionMatchIterator it = filePathRegex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            QString path = match.captured(0);
            if (path.length() < 5) continue;
            
            IOC ioc;
            ioc.type = IOC::FILE_PATH;
            ioc.value = path;
            ioc.defanged = path;
            ioc.isSuspicious = path.contains("\\Temp\\", Qt::CaseInsensitive) ||
                              path.contains("\\AppData\\", Qt::CaseInsensitive) ||
                              path.contains("/tmp/") ||
                              path.endsWith(".exe") ||
                              path.endsWith(".dll") ||
                              path.endsWith(".bat") ||
                              path.endsWith(".ps1");
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractRegistryKeys(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        QRegularExpressionMatchIterator it = registryRegex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::REGISTRY_KEY;
            ioc.value = match.captured(0);
            ioc.defanged = ioc.value;
            ioc.isSuspicious = ioc.value.contains("\\Run", Qt::CaseInsensitive) ||
                              ioc.value.contains("\\RunOnce", Qt::CaseInsensitive) ||
                              ioc.value.contains("\\Services", Qt::CaseInsensitive) ||
                              ioc.value.contains("\\Explorer\\Shell", Qt::CaseInsensitive);
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractHashes(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        // SHA256
        QRegularExpressionMatchIterator it = sha256Regex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::HASH_SHA256;
            ioc.value = match.captured(0).toLower();
            ioc.defanged = ioc.value;
            ioc.isSuspicious = false;
            iocs.append(ioc);
        }
        
        // SHA1
        it = sha1Regex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::HASH_SHA1;
            ioc.value = match.captured(0).toLower();
            ioc.defanged = ioc.value;
            ioc.isSuspicious = false;
            iocs.append(ioc);
        }
        
        // MD5
        it = md5Regex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::HASH_MD5;
            ioc.value = match.captured(0).toLower();
            ioc.defanged = ioc.value;
            ioc.isSuspicious = false;
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QList<IOC> IOCExtractor::extractBitcoinAddresses(const QStringList &strings)
{
    QList<IOC> iocs;
    
    for (const QString &str : strings) {
        QRegularExpressionMatchIterator it = bitcoinRegex.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            IOC ioc;
            ioc.type = IOC::BITCOIN_ADDRESS;
            ioc.value = match.captured(0);
            ioc.defanged = ioc.value;
            ioc.isSuspicious = true; // Bitcoin addresses in malware are suspicious
            iocs.append(ioc);
        }
    }
    
    return iocs;
}

QString IOCExtractor::defang(const QString &ioc, IOC::Type type)
{
    QString defanged = ioc;
    
    switch (type) {
        case IOC::URL:
            defanged.replace("http://", "hxxp://");
            defanged.replace("https://", "hxxps://");
            defanged.replace("ftp://", "fxp://");
            defanged.replace(".", "[.]");
            break;
        case IOC::IP_ADDRESS:
            defanged.replace(".", "[.]");
            break;
        case IOC::DOMAIN:
            defanged.replace(".", "[.]");
            break;
        case IOC::EMAIL:
            defanged.replace("@", "[@]");
            defanged.replace(".", "[.]");
            break;
        default:
            break;
    }
    
    return defanged;
}

QString IOCExtractor::refang(const QString &defanged, IOC::Type type)
{
    QString refanged = defanged;
    
    refanged.replace("hxxp://", "http://");
    refanged.replace("hxxps://", "https://");
    refanged.replace("fxp://", "ftp://");
    refanged.replace("[.]", ".");
    refanged.replace("[@]", "@");
    
    return refanged;
}

QString IOCExtractor::exportToText(const QList<IOC> &iocs)
{
    QString output;
    output += "# IOC Report\n";
    output += "# Generated by PE-bear\n\n";
    
    QMap<IOC::Type, QStringList> grouped;
    for (const IOC &ioc : iocs) {
        grouped[ioc.type].append(ioc.defanged);
    }
    
    for (auto it = grouped.begin(); it != grouped.end(); ++it) {
        output += "## " + getIOCTypeName(it.key()) + "\n";
        for (const QString &value : it.value()) {
            output += value + "\n";
        }
        output += "\n";
    }
    
    return output;
}

QString IOCExtractor::exportToCSV(const QList<IOC> &iocs)
{
    QString output;
    output += "type,value,defanged,suspicious\n";
    
    for (const IOC &ioc : iocs) {
        output += QString("\"%1\",\"%2\",\"%3\",%4\n")
            .arg(getIOCTypeName(ioc.type))
            .arg(ioc.value)
            .arg(ioc.defanged)
            .arg(ioc.isSuspicious ? "true" : "false");
    }
    
    return output;
}

QString IOCExtractor::exportToJSON(const QList<IOC> &iocs)
{
    QJsonArray array;
    
    for (const IOC &ioc : iocs) {
        QJsonObject obj;
        obj["type"] = getIOCTypeName(ioc.type);
        obj["value"] = ioc.value;
        obj["defanged"] = ioc.defanged;
        obj["suspicious"] = ioc.isSuspicious;
        array.append(obj);
    }
    
    QJsonDocument doc(array);
    return doc.toJson(QJsonDocument::Indented);
}

QString IOCExtractor::exportToSTIX(const QList<IOC> &iocs)
{
    // Simplified STIX 2.1 format
    QJsonObject bundle;
    bundle["type"] = "bundle";
    bundle["id"] = "bundle--" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    
    QJsonArray objects;
    
    for (const IOC &ioc : iocs) {
        QJsonObject obj;
        obj["type"] = "indicator";
        obj["id"] = "indicator--" + QUuid::createUuid().toString(QUuid::WithoutBraces);
        obj["created"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        
        QString stixType;
        switch (ioc.type) {
            case IOC::URL: stixType = "url:value"; break;
            case IOC::IP_ADDRESS: stixType = "ipv4-addr:value"; break;
            case IOC::DOMAIN: stixType = "domain-name:value"; break;
            case IOC::EMAIL: stixType = "email-addr:value"; break;
            case IOC::HASH_MD5: stixType = "file:hashes.MD5"; break;
            case IOC::HASH_SHA1: stixType = "file:hashes.SHA1"; break;
            case IOC::HASH_SHA256: stixType = "file:hashes.SHA256"; break;
            default: stixType = "artifact:payload_bin"; break;
        }
        
        obj["pattern"] = QString("[%1 = '%2']").arg(stixType).arg(ioc.value);
        obj["pattern_type"] = "stix";
        obj["valid_from"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        
        objects.append(obj);
    }
    
    bundle["objects"] = objects;
    
    QJsonDocument doc(bundle);
    return doc.toJson(QJsonDocument::Indented);
}

bool IOCExtractor::isPrivateIP(const QString &ip)
{
    // Check for private IP ranges
    if (ip.startsWith("10.") || 
        ip.startsWith("192.168.") ||
        ip.startsWith("127.")) {
        return true;
    }
    
    // 172.16.0.0 - 172.31.255.255
    if (ip.startsWith("172.")) {
        QStringList parts = ip.split(".");
        if (parts.size() >= 2) {
            int second = parts[1].toInt();
            if (second >= 16 && second <= 31) {
                return true;
            }
        }
    }
    
    return false;
}

bool IOCExtractor::isLocalhost(const QString &value)
{
    return value == "127.0.0.1" || 
           value == "localhost" || 
           value == "::1";
}

QString IOCExtractor::getIOCTypeName(IOC::Type type)
{
    switch (type) {
        case IOC::URL: return "URL";
        case IOC::IP_ADDRESS: return "IP Address";
        case IOC::DOMAIN: return "Domain";
        case IOC::EMAIL: return "Email";
        case IOC::FILE_PATH: return "File Path";
        case IOC::REGISTRY_KEY: return "Registry Key";
        case IOC::BITCOIN_ADDRESS: return "Bitcoin Address";
        case IOC::HASH_MD5: return "MD5 Hash";
        case IOC::HASH_SHA1: return "SHA1 Hash";
        case IOC::HASH_SHA256: return "SHA256 Hash";
        case IOC::USER_AGENT: return "User Agent";
        case IOC::MUTEX: return "Mutex";
        default: return "Unknown";
    }
}

QString IOCExtractor::typeToString(IOC::Type type)
{
    return getIOCTypeName(type);
}

bool IOCExtractor::checkMaliciousDomain(const QString &domain)
{
    return knownMaliciousDomains.contains(domain.toLower());
}

bool IOCExtractor::checkMaliciousIP(const QString &ip)
{
    // In real implementation, check against threat intel feeds
    return false;
}
