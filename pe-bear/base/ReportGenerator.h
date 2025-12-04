#pragma once

#include <QtCore>
#include <QObject>
#include "YaraScanner.h"
#include "EntropyAnalyzer.h"
#include "ShellcodeDetector.h"
#include "IOCExtractor.h"
#include "UnpackerDetector.h"
#include "AIAnalyzer.h"

struct AnalysisReport {
    // File info
    QString fileName;
    QString filePath;
    qint64 fileSize;
    QString md5Hash;
    QString sha1Hash;
    QString sha256Hash;
    QDateTime analysisTime;
    
    // PE info
    QString peType; // 32-bit, 64-bit
    QString subsystem;
    QString compiler;
    QDateTime compileTime;
    int numberOfSections;
    int numberOfImports;
    int numberOfExports;
    QString entryPoint;
    QString imageBase;
    
    // Security analysis
    bool hasASLR;
    bool hasDEP;
    bool hasCFG;
    bool hasSEH;
    bool hasSafeSEH;
    bool isHighEntropyVA;
    bool isSignedBinary;
    
    // Entropy analysis
    double overallEntropy;
    QList<QPair<QString, double>> sectionEntropies;
    bool isProbablyPacked;
    bool isProbablyEncrypted;
    
    // Packer detection
    QList<PackerInfo> detectedPackers;
    
    // IOC results
    QList<IOC> extractedIOCs;
    
    // Shellcode detection
    QList<ShellcodeMatch> shellcodeMatches;
    
    // YARA matches
    QList<YaraMatch> yaraMatches;
    
    // AI Analysis
    QString aiMalwareAnalysis;
    QString aiVulnerabilityAnalysis;
    
    // Summary
    QString riskLevel; // Low, Medium, High, Critical
    QStringList findings;
    QStringList recommendations;
};

enum class ReportFormat {
    HTML,
    Markdown,
    JSON,
    XML,
    PlainText,
    PDF // Requires external tool
};

class ReportGenerator : public QObject
{
    Q_OBJECT

signals:
    void reportGenerated(const QString &path);
    void reportError(const QString &error);
    void progressUpdate(int percent, const QString &status);

public:
    explicit ReportGenerator(QObject *parent = nullptr);
    ~ReportGenerator();

    // Generate report
    bool generateReport(const AnalysisReport &report, const QString &outputPath, ReportFormat format);
    
    // Format-specific generators
    QString generateHTML(const AnalysisReport &report);
    QString generateMarkdown(const AnalysisReport &report);
    QString generateJSON(const AnalysisReport &report);
    QString generateXML(const AnalysisReport &report);
    QString generatePlainText(const AnalysisReport &report);
    bool generatePDF(const AnalysisReport &report, const QString &outputPath);
    
    // Helpers
    static QString riskLevelColor(const QString &level);
    static QString formatBytes(qint64 bytes);
    static QString escapeHtml(const QString &text);
    static QString escapeXml(const QString &text);
    
    // Template customization
    void setCustomCSS(const QString &css);
    void setCompanyLogo(const QString &logoPath);
    void setReportTitle(const QString &title);
    void setAnalystName(const QString &name);

private:
    QString customCSS;
    QString companyLogo;
    QString reportTitle;
    QString analystName;
    
    QString getDefaultCSS();
    QString generateHTMLHeader(const AnalysisReport &report);
    QString generateHTMLSummary(const AnalysisReport &report);
    QString generateHTMLFileInfo(const AnalysisReport &report);
    QString generateHTMLSecurityInfo(const AnalysisReport &report);
    QString generateHTMLEntropyInfo(const AnalysisReport &report);
    QString generateHTMLPackerInfo(const AnalysisReport &report);
    QString generateHTMLIOCInfo(const AnalysisReport &report);
    QString generateHTMLShellcodeInfo(const AnalysisReport &report);
    QString generateHTMLYaraInfo(const AnalysisReport &report);
    QString generateHTMLAIAnalysis(const AnalysisReport &report);
    QString generateHTMLFooter(const AnalysisReport &report);
};
