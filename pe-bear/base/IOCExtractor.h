#pragma once

#include <QtCore>
#include <QObject>

typedef uint64_t offset_t;

struct IOC {
    enum Type {
        URL,
        IP_ADDRESS,
        DOMAIN,
        EMAIL,
        FILE_PATH,
        REGISTRY_KEY,
        BITCOIN_ADDRESS,
        HASH_MD5,
        HASH_SHA1,
        HASH_SHA256,
        USER_AGENT,
        MUTEX,
        UNKNOWN
    };
    
    Type type;
    QString value;
    QString defanged;
    offset_t offset;
    bool isSuspicious;
    QString context;
};

class IOCExtractor : public QObject
{
    Q_OBJECT

signals:
    void extractionComplete(const QList<IOC> &iocs);
    void extractionError(const QString &error);

public:
    explicit IOCExtractor(QObject *parent = nullptr);
    ~IOCExtractor();

    // Extraction
    QList<IOC> extractAll(const QStringList &strings);
    QList<IOC> extractFromBinary(const QByteArray &data);
    
    // Specific extractors
    QList<IOC> extractURLs(const QStringList &strings);
    QList<IOC> extractIPs(const QStringList &strings);
    QList<IOC> extractDomains(const QStringList &strings);
    QList<IOC> extractEmails(const QStringList &strings);
    QList<IOC> extractFilePaths(const QStringList &strings);
    QList<IOC> extractRegistryKeys(const QStringList &strings);
    QList<IOC> extractHashes(const QStringList &strings);
    QList<IOC> extractBitcoinAddresses(const QStringList &strings);
    
    // Defanging (safe for sharing)
    static QString defang(const QString &ioc, IOC::Type type);
    static QString refang(const QString &defanged, IOC::Type type);
    
    // Export
    QString exportToText(const QList<IOC> &iocs);
    QString exportToCSV(const QList<IOC> &iocs);
    QString exportToJSON(const QList<IOC> &iocs);
    QString exportToSTIX(const QList<IOC> &iocs);
    
    // Analysis helpers
    static bool isPrivateIP(const QString &ip);
    static bool isLocalhost(const QString &value);
    static QString getIOCTypeName(IOC::Type type);
    
    // Threat intel (basic)
    bool checkMaliciousDomain(const QString &domain);
    bool checkMaliciousIP(const QString &ip);

private:
    static QRegularExpression urlRegex;
    static QRegularExpression ipv4Regex;
    static QRegularExpression ipv6Regex;
    static QRegularExpression domainRegex;
    static QRegularExpression emailRegex;
    static QRegularExpression filePathRegex;
    static QRegularExpression registryRegex;
    static QRegularExpression md5Regex;
    static QRegularExpression sha1Regex;
    static QRegularExpression sha256Regex;
    static QRegularExpression bitcoinRegex;
    
    void initRegexes();
    bool regexesInitialized;
    
    QSet<QString> knownMaliciousDomains;
    void loadKnownMalicious();
};
