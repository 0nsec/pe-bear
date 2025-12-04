#pragma once

#include <QtCore>
#include <QObject>

typedef uint64_t offset_t;

struct ShellcodeMatch {
    QString patternName;
    QString description;
    offset_t offset;
    size_t size;
    QByteArray data;
    QString platform;      // windows, linux, etc.
    QString architecture;  // x86, x64, arm
    double confidence;     // 0.0 - 1.0
};

class ShellcodeDetector : public QObject
{
    Q_OBJECT

signals:
    void detectionComplete(const QList<ShellcodeMatch> &matches);
    void detectionError(const QString &error);
    void detectionProgress(int percent, const QString &status);

public:
    explicit ShellcodeDetector(QObject *parent = nullptr);
    ~ShellcodeDetector();

    // Detection
    QList<ShellcodeMatch> scanForShellcode(const QByteArray &data);
    QList<ShellcodeMatch> scanSection(const QByteArray &data, const QString &sectionName, offset_t baseOffset = 0);
    
    // Extraction
    QByteArray extractShellcode(const QByteArray &data, offset_t offset, size_t maxSize = 0x1000);
    bool saveShellcode(const ShellcodeMatch &match, const QString &filePath);
    
    // Analysis
    QString analyzeShellcode(const QByteArray &shellcode);
    QStringList identifyCapabilities(const QByteArray &shellcode);
    
    // Export
    QString toNasmSyntax(const QByteArray &shellcode);
    QString toCArray(const QByteArray &shellcode);
    QString toPythonArray(const QByteArray &shellcode);

private:
    struct ShellcodePattern {
        QString name;
        QString description;
        QByteArray pattern;
        QByteArray mask;  // 0xFF = match, 0x00 = wildcard
        QString platform;
        QString arch;
    };
    
    QList<ShellcodePattern> patterns;
    void initializePatterns();
    
    bool matchPattern(const QByteArray &data, offset_t offset, const ShellcodePattern &pattern);
    size_t findShellcodeEnd(const QByteArray &data, offset_t start);
};
