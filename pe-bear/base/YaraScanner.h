#pragma once

#include <QtCore>
#include <QObject>

typedef uint64_t offset_t;

// YARA match result structure
struct YaraMatch {
    QString ruleName;
    QString namespaceName;
    QStringList tags;
    QMap<QString, QString> metadata;
    QList<QPair<offset_t, size_t>> matches; // offset, length pairs
    QString description;
};

class YaraScanner : public QObject
{
    Q_OBJECT

signals:
    void scanComplete(const QList<YaraMatch> &matches);
    void scanError(const QString &error);
    void scanProgress(int percent, const QString &status);

public:
    explicit YaraScanner(QObject *parent = nullptr);
    ~YaraScanner();

    // Scan functions
    bool scanFile(const QString &filePath, const QString &rulesPath);
    bool scanBuffer(const QByteArray &data, const QString &rulesPath);
    bool scanWithRules(const QByteArray &data, const QString &rulesContent);
    
    // Rule management
    bool compileRules(const QString &rulesPath, QString &errorMsg);
    bool validateRule(const QString &ruleContent, QString &errorMsg);
    
    // Community rules
    static QStringList getAvailableRuleSets();
    bool downloadRuleSet(const QString &name, const QString &savePath);
    
    // Built-in rules for common malware patterns
    static QString getBuiltInRules();

private:
    QString lastError;
    
    // Simple pattern matching (fallback without libyara)
    QList<YaraMatch> simplePatternScan(const QByteArray &data, const QString &rulesContent);
    QList<QPair<QString, QByteArray>> parseSimpleRules(const QString &rulesContent);
};
