#include "ReportGenerator.h"
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>
#include <QXmlStreamWriter>

ReportGenerator::ReportGenerator(QObject *parent)
    : QObject(parent)
    , reportTitle("PE Analysis Report")
    , analystName("PE-bear")
{
}

ReportGenerator::~ReportGenerator()
{
}

bool ReportGenerator::generateReport(const AnalysisReport &report, const QString &outputPath, ReportFormat format)
{
    emit progressUpdate(10, "Generating report...");
    
    QString content;
    bool success = false;
    
    switch (format) {
        case ReportFormat::HTML:
            content = generateHTML(report);
            break;
        case ReportFormat::Markdown:
            content = generateMarkdown(report);
            break;
        case ReportFormat::JSON:
            content = generateJSON(report);
            break;
        case ReportFormat::XML:
            content = generateXML(report);
            break;
        case ReportFormat::PlainText:
            content = generatePlainText(report);
            break;
        case ReportFormat::PDF:
            return generatePDF(report, outputPath);
    }
    
    emit progressUpdate(80, "Writing to file...");
    
    QFile file(outputPath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream.setEncoding(QStringConverter::Utf8);
        stream << content;
        file.close();
        success = true;
    } else {
        emit reportError("Failed to write report: " + file.errorString());
        return false;
    }
    
    emit progressUpdate(100, "Report generated!");
    emit reportGenerated(outputPath);
    return success;
}

QString ReportGenerator::generateHTML(const AnalysisReport &report)
{
    QString html;
    html += "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n";
    html += "<meta charset=\"UTF-8\">\n";
    html += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html += "<title>" + escapeHtml(reportTitle) + " - " + escapeHtml(report.fileName) + "</title>\n";
    html += "<style>\n" + (customCSS.isEmpty() ? getDefaultCSS() : customCSS) + "\n</style>\n";
    html += "</head>\n<body>\n";
    
    html += generateHTMLHeader(report);
    html += generateHTMLSummary(report);
    html += generateHTMLFileInfo(report);
    html += generateHTMLSecurityInfo(report);
    html += generateHTMLEntropyInfo(report);
    html += generateHTMLPackerInfo(report);
    html += generateHTMLIOCInfo(report);
    html += generateHTMLShellcodeInfo(report);
    html += generateHTMLYaraInfo(report);
    html += generateHTMLAIAnalysis(report);
    html += generateHTMLFooter(report);
    
    html += "</body>\n</html>";
    return html;
}

QString ReportGenerator::generateMarkdown(const AnalysisReport &report)
{
    QString md;
    
    // Header
    md += "# " + reportTitle + "\n\n";
    md += "**File:** " + report.fileName + "\n\n";
    md += "**Analysis Date:** " + report.analysisTime.toString(Qt::ISODate) + "\n\n";
    md += "---\n\n";
    
    // Executive Summary
    md += "## Executive Summary\n\n";
    md += "**Risk Level:** " + report.riskLevel + "\n\n";
    
    if (!report.findings.isEmpty()) {
        md += "### Key Findings\n\n";
        for (const QString &finding : report.findings) {
            md += "- " + finding + "\n";
        }
        md += "\n";
    }
    
    if (!report.recommendations.isEmpty()) {
        md += "### Recommendations\n\n";
        for (const QString &rec : report.recommendations) {
            md += "- " + rec + "\n";
        }
        md += "\n";
    }
    
    // File Information
    md += "## File Information\n\n";
    md += "| Property | Value |\n";
    md += "|----------|-------|\n";
    md += "| File Name | " + report.fileName + " |\n";
    md += "| File Size | " + formatBytes(report.fileSize) + " |\n";
    md += "| MD5 | `" + report.md5Hash + "` |\n";
    md += "| SHA-1 | `" + report.sha1Hash + "` |\n";
    md += "| SHA-256 | `" + report.sha256Hash + "` |\n";
    md += "| PE Type | " + report.peType + " |\n";
    md += "| Compiler | " + report.compiler + " |\n";
    md += "| Compile Time | " + report.compileTime.toString(Qt::ISODate) + " |\n";
    md += "| Entry Point | " + report.entryPoint + " |\n";
    md += "| Image Base | " + report.imageBase + " |\n\n";
    
    // Security Features
    md += "## Security Features\n\n";
    md += "| Feature | Status |\n";
    md += "|---------|--------|\n";
    md += "| ASLR | " + QString(report.hasASLR ? "✅ Enabled" : "❌ Disabled") + " |\n";
    md += "| DEP/NX | " + QString(report.hasDEP ? "✅ Enabled" : "❌ Disabled") + " |\n";
    md += "| CFG | " + QString(report.hasCFG ? "✅ Enabled" : "❌ Disabled") + " |\n";
    md += "| SEH | " + QString(report.hasSEH ? "✅ Present" : "❌ Not Present") + " |\n";
    md += "| SafeSEH | " + QString(report.hasSafeSEH ? "✅ Enabled" : "❌ Disabled") + " |\n";
    md += "| High Entropy VA | " + QString(report.isHighEntropyVA ? "✅ Enabled" : "❌ Disabled") + " |\n";
    md += "| Code Signing | " + QString(report.isSignedBinary ? "✅ Signed" : "❌ Not Signed") + " |\n\n";
    
    // Entropy Analysis
    md += "## Entropy Analysis\n\n";
    md += "**Overall Entropy:** " + QString::number(report.overallEntropy, 'f', 4) + "\n\n";
    
    if (report.isProbablyPacked) {
        md += "⚠️ **Warning:** File appears to be packed\n\n";
    }
    if (report.isProbablyEncrypted) {
        md += "⚠️ **Warning:** File contains encrypted sections\n\n";
    }
    
    if (!report.sectionEntropies.isEmpty()) {
        md += "### Section Entropies\n\n";
        md += "| Section | Entropy |\n";
        md += "|---------|----------|\n";
        for (const auto &pair : report.sectionEntropies) {
            md += "| " + pair.first + " | " + QString::number(pair.second, 'f', 4) + " |\n";
        }
        md += "\n";
    }
    
    // Packer Detection
    if (!report.detectedPackers.isEmpty()) {
        md += "## Packer Detection\n\n";
        for (const PackerInfo &packer : report.detectedPackers) {
            md += "### " + packer.name + "\n\n";
            md += "- **Version:** " + packer.version + "\n";
            md += "- **Description:** " + packer.description + "\n";
            md += "- **Confidence:** " + QString::number(packer.confidence * 100, 'f', 1) + "%\n";
            md += "- **Can Unpack:** " + QString(packer.canUnpack ? "Yes" : "No") + "\n\n";
        }
    }
    
    // IOC Extraction
    if (!report.extractedIOCs.isEmpty()) {
        md += "## Indicators of Compromise\n\n";
        md += "| Type | Value | Context |\n";
        md += "|------|-------|----------|\n";
        for (const IOC &ioc : report.extractedIOCs) {
            md += "| " + IOCExtractor::typeToString(ioc.type) + " | `" + ioc.value + "` | " + ioc.context + " |\n";
        }
        md += "\n";
    }
    
    // Shellcode Detection
    if (!report.shellcodeMatches.isEmpty()) {
        md += "## Shellcode Detection\n\n";
        md += "⚠️ **Warning:** Potential shellcode detected!\n\n";
        for (const ShellcodeMatch &match : report.shellcodeMatches) {
            md += "- **" + match.patternName + "** at offset 0x" + QString::number(match.offset, 16).toUpper() + " (Confidence: " + QString::number(match.confidence * 100, 'f', 1) + "%)\n";
        }
        md += "\n";
    }
    
    // YARA Matches
    if (!report.yaraMatches.isEmpty()) {
        md += "## YARA Rule Matches\n\n";
        for (const YaraMatch &match : report.yaraMatches) {
            md += "### Rule: " + match.ruleName + "\n\n";
            md += "- **Tags:** " + match.tags.join(", ") + "\n";
            md += "- **Description:** " + match.description + "\n\n";
        }
    }
    
    // AI Analysis
    if (!report.aiMalwareAnalysis.isEmpty() || !report.aiVulnerabilityAnalysis.isEmpty()) {
        md += "## AI-Powered Analysis\n\n";
        
        if (!report.aiMalwareAnalysis.isEmpty()) {
            md += "### Malware Analysis\n\n";
            md += report.aiMalwareAnalysis + "\n\n";
        }
        
        if (!report.aiVulnerabilityAnalysis.isEmpty()) {
            md += "### Vulnerability Analysis\n\n";
            md += report.aiVulnerabilityAnalysis + "\n\n";
        }
    }
    
    // Footer
    md += "---\n\n";
    md += "*Generated by " + analystName + " on " + report.analysisTime.toString(Qt::ISODate) + "*\n";
    
    return md;
}

QString ReportGenerator::generateJSON(const AnalysisReport &report)
{
    QJsonObject root;
    
    // Metadata
    QJsonObject metadata;
    metadata["reportTitle"] = reportTitle;
    metadata["generatedBy"] = analystName;
    metadata["analysisTime"] = report.analysisTime.toString(Qt::ISODate);
    root["metadata"] = metadata;
    
    // File info
    QJsonObject fileInfo;
    fileInfo["fileName"] = report.fileName;
    fileInfo["filePath"] = report.filePath;
    fileInfo["fileSize"] = report.fileSize;
    fileInfo["md5"] = report.md5Hash;
    fileInfo["sha1"] = report.sha1Hash;
    fileInfo["sha256"] = report.sha256Hash;
    root["fileInfo"] = fileInfo;
    
    // PE info
    QJsonObject peInfo;
    peInfo["type"] = report.peType;
    peInfo["subsystem"] = report.subsystem;
    peInfo["compiler"] = report.compiler;
    peInfo["compileTime"] = report.compileTime.toString(Qt::ISODate);
    peInfo["sections"] = report.numberOfSections;
    peInfo["imports"] = report.numberOfImports;
    peInfo["exports"] = report.numberOfExports;
    peInfo["entryPoint"] = report.entryPoint;
    peInfo["imageBase"] = report.imageBase;
    root["peInfo"] = peInfo;
    
    // Security
    QJsonObject security;
    security["aslr"] = report.hasASLR;
    security["dep"] = report.hasDEP;
    security["cfg"] = report.hasCFG;
    security["seh"] = report.hasSEH;
    security["safeSeh"] = report.hasSafeSEH;
    security["highEntropyVA"] = report.isHighEntropyVA;
    security["signed"] = report.isSignedBinary;
    root["security"] = security;
    
    // Entropy
    QJsonObject entropy;
    entropy["overall"] = report.overallEntropy;
    entropy["isPacked"] = report.isProbablyPacked;
    entropy["isEncrypted"] = report.isProbablyEncrypted;
    
    QJsonArray sections;
    for (const auto &pair : report.sectionEntropies) {
        QJsonObject section;
        section["name"] = pair.first;
        section["entropy"] = pair.second;
        sections.append(section);
    }
    entropy["sections"] = sections;
    root["entropy"] = entropy;
    
    // Packers
    QJsonArray packers;
    for (const PackerInfo &packer : report.detectedPackers) {
        QJsonObject p;
        p["name"] = packer.name;
        p["version"] = packer.version;
        p["description"] = packer.description;
        p["confidence"] = packer.confidence;
        p["canUnpack"] = packer.canUnpack;
        packers.append(p);
    }
    root["packers"] = packers;
    
    // IOCs
    QJsonArray iocs;
    for (const IOC &ioc : report.extractedIOCs) {
        QJsonObject i;
        i["type"] = IOCExtractor::typeToString(ioc.type);
        i["value"] = ioc.value;
        i["context"] = ioc.context;
        i["confidence"] = ioc.confidence;
        iocs.append(i);
    }
    root["iocs"] = iocs;
    
    // Shellcode
    QJsonArray shellcode;
    for (const ShellcodeMatch &match : report.shellcodeMatches) {
        QJsonObject s;
        s["pattern"] = match.patternName;
        s["offset"] = QString::number(match.offset, 16);
        s["size"] = match.size;
        s["confidence"] = match.confidence;
        s["description"] = match.description;
        shellcode.append(s);
    }
    root["shellcode"] = shellcode;
    
    // YARA
    QJsonArray yara;
    for (const YaraMatch &match : report.yaraMatches) {
        QJsonObject y;
        y["rule"] = match.ruleName;
        y["namespace"] = match.namespaceName;
        y["tags"] = QJsonArray::fromStringList(match.tags);
        y["description"] = match.description;
        yara.append(y);
    }
    root["yaraMatches"] = yara;
    
    // AI Analysis
    QJsonObject ai;
    ai["malwareAnalysis"] = report.aiMalwareAnalysis;
    ai["vulnerabilityAnalysis"] = report.aiVulnerabilityAnalysis;
    root["aiAnalysis"] = ai;
    
    // Summary
    QJsonObject summary;
    summary["riskLevel"] = report.riskLevel;
    summary["findings"] = QJsonArray::fromStringList(report.findings);
    summary["recommendations"] = QJsonArray::fromStringList(report.recommendations);
    root["summary"] = summary;
    
    QJsonDocument doc(root);
    return doc.toJson(QJsonDocument::Indented);
}

QString ReportGenerator::generateXML(const AnalysisReport &report)
{
    QString xml;
    QXmlStreamWriter writer(&xml);
    writer.setAutoFormatting(true);
    writer.setAutoFormattingIndent(2);
    
    writer.writeStartDocument();
    writer.writeStartElement("AnalysisReport");
    writer.writeAttribute("version", "1.0");
    
    // Metadata
    writer.writeStartElement("Metadata");
    writer.writeTextElement("ReportTitle", reportTitle);
    writer.writeTextElement("GeneratedBy", analystName);
    writer.writeTextElement("AnalysisTime", report.analysisTime.toString(Qt::ISODate));
    writer.writeEndElement();
    
    // File Info
    writer.writeStartElement("FileInfo");
    writer.writeTextElement("FileName", report.fileName);
    writer.writeTextElement("FilePath", report.filePath);
    writer.writeTextElement("FileSize", QString::number(report.fileSize));
    writer.writeTextElement("MD5", report.md5Hash);
    writer.writeTextElement("SHA1", report.sha1Hash);
    writer.writeTextElement("SHA256", report.sha256Hash);
    writer.writeEndElement();
    
    // PE Info
    writer.writeStartElement("PEInfo");
    writer.writeTextElement("Type", report.peType);
    writer.writeTextElement("Subsystem", report.subsystem);
    writer.writeTextElement("Compiler", report.compiler);
    writer.writeTextElement("CompileTime", report.compileTime.toString(Qt::ISODate));
    writer.writeTextElement("Sections", QString::number(report.numberOfSections));
    writer.writeTextElement("Imports", QString::number(report.numberOfImports));
    writer.writeTextElement("Exports", QString::number(report.numberOfExports));
    writer.writeTextElement("EntryPoint", report.entryPoint);
    writer.writeTextElement("ImageBase", report.imageBase);
    writer.writeEndElement();
    
    // Security Features
    writer.writeStartElement("Security");
    writer.writeTextElement("ASLR", report.hasASLR ? "true" : "false");
    writer.writeTextElement("DEP", report.hasDEP ? "true" : "false");
    writer.writeTextElement("CFG", report.hasCFG ? "true" : "false");
    writer.writeTextElement("SEH", report.hasSEH ? "true" : "false");
    writer.writeTextElement("SafeSEH", report.hasSafeSEH ? "true" : "false");
    writer.writeTextElement("HighEntropyVA", report.isHighEntropyVA ? "true" : "false");
    writer.writeTextElement("Signed", report.isSignedBinary ? "true" : "false");
    writer.writeEndElement();
    
    // Summary
    writer.writeStartElement("Summary");
    writer.writeTextElement("RiskLevel", report.riskLevel);
    writer.writeStartElement("Findings");
    for (const QString &finding : report.findings) {
        writer.writeTextElement("Finding", finding);
    }
    writer.writeEndElement();
    writer.writeStartElement("Recommendations");
    for (const QString &rec : report.recommendations) {
        writer.writeTextElement("Recommendation", rec);
    }
    writer.writeEndElement();
    writer.writeEndElement();
    
    writer.writeEndElement(); // AnalysisReport
    writer.writeEndDocument();
    
    return xml;
}

QString ReportGenerator::generatePlainText(const AnalysisReport &report)
{
    QString text;
    
    text += "=" + QString("=").repeated(60) + "\n";
    text += "                    " + reportTitle + "\n";
    text += "=" + QString("=").repeated(60) + "\n\n";
    
    text += "File: " + report.fileName + "\n";
    text += "Date: " + report.analysisTime.toString(Qt::ISODate) + "\n";
    text += "-" + QString("-").repeated(60) + "\n\n";
    
    // Risk Level
    text += "RISK LEVEL: " + report.riskLevel + "\n\n";
    
    // Findings
    if (!report.findings.isEmpty()) {
        text += "KEY FINDINGS:\n";
        for (const QString &finding : report.findings) {
            text += "  * " + finding + "\n";
        }
        text += "\n";
    }
    
    // File Info
    text += "FILE INFORMATION\n";
    text += "-" + QString("-").repeated(40) + "\n";
    text += "  Size:        " + formatBytes(report.fileSize) + "\n";
    text += "  MD5:         " + report.md5Hash + "\n";
    text += "  SHA-1:       " + report.sha1Hash + "\n";
    text += "  SHA-256:     " + report.sha256Hash + "\n";
    text += "  PE Type:     " + report.peType + "\n";
    text += "  Entry Point: " + report.entryPoint + "\n";
    text += "\n";
    
    // Security
    text += "SECURITY FEATURES\n";
    text += "-" + QString("-").repeated(40) + "\n";
    text += "  ASLR:           " + QString(report.hasASLR ? "Enabled" : "DISABLED") + "\n";
    text += "  DEP/NX:         " + QString(report.hasDEP ? "Enabled" : "DISABLED") + "\n";
    text += "  CFG:            " + QString(report.hasCFG ? "Enabled" : "DISABLED") + "\n";
    text += "  Code Signing:   " + QString(report.isSignedBinary ? "Signed" : "NOT SIGNED") + "\n";
    text += "\n";
    
    // Entropy
    text += "ENTROPY ANALYSIS\n";
    text += "-" + QString("-").repeated(40) + "\n";
    text += "  Overall Entropy: " + QString::number(report.overallEntropy, 'f', 4) + "\n";
    if (report.isProbablyPacked) {
        text += "  WARNING: File appears to be PACKED\n";
    }
    text += "\n";
    
    // Packers
    if (!report.detectedPackers.isEmpty()) {
        text += "DETECTED PACKERS\n";
        text += "-" + QString("-").repeated(40) + "\n";
        for (const PackerInfo &p : report.detectedPackers) {
            text += "  " + p.name + " " + p.version + " (Confidence: " + QString::number(p.confidence * 100, 'f', 0) + "%)\n";
        }
        text += "\n";
    }
    
    // IOCs
    if (!report.extractedIOCs.isEmpty()) {
        text += "INDICATORS OF COMPROMISE\n";
        text += "-" + QString("-").repeated(40) + "\n";
        for (const IOC &ioc : report.extractedIOCs) {
            text += "  [" + IOCExtractor::typeToString(ioc.type) + "] " + ioc.value + "\n";
        }
        text += "\n";
    }
    
    // Footer
    text += "=" + QString("=").repeated(60) + "\n";
    text += "Generated by " + analystName + "\n";
    
    return text;
}

bool ReportGenerator::generatePDF(const AnalysisReport &report, const QString &outputPath)
{
    // Generate HTML first
    QString html = generateHTML(report);
    QString htmlPath = outputPath + ".html";
    
    // Write HTML temporarily
    QFile htmlFile(htmlPath);
    if (!htmlFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit reportError("Failed to create temporary HTML file");
        return false;
    }
    
    QTextStream stream(&htmlFile);
    stream << html;
    htmlFile.close();
    
    // Try using wkhtmltopdf if available
    QProcess process;
    process.start("wkhtmltopdf", {"--enable-local-file-access", htmlPath, outputPath});
    
    if (!process.waitForStarted(5000)) {
        // Try pandoc as fallback
        process.start("pandoc", {htmlPath, "-o", outputPath, "--pdf-engine=wkhtmltopdf"});
        if (!process.waitForStarted(5000)) {
            emit reportError("PDF generation requires wkhtmltopdf or pandoc. Please install one of them.");
            QFile::remove(htmlPath);
            return false;
        }
    }
    
    if (!process.waitForFinished(60000)) {
        emit reportError("PDF generation timed out");
        process.kill();
        QFile::remove(htmlPath);
        return false;
    }
    
    // Clean up temp HTML
    QFile::remove(htmlPath);
    
    if (process.exitCode() != 0) {
        emit reportError("PDF generation failed: " + QString::fromUtf8(process.readAllStandardError()));
        return false;
    }
    
    emit progressUpdate(100, "PDF generated!");
    emit reportGenerated(outputPath);
    return true;
}

QString ReportGenerator::getDefaultCSS()
{
    return R"(
        :root {
            --primary: #0078d4;
            --danger: #d13438;
            --warning: #f7630c;
            --success: #107c10;
            --bg: #ffffff;
            --bg-secondary: #f3f2f1;
            --text: #323130;
            --border: #edebe9;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text);
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: var(--bg);
        }
        
        h1, h2, h3 { color: var(--primary); }
        
        h1 { 
            border-bottom: 3px solid var(--primary);
            padding-bottom: 10px;
        }
        
        h2 {
            border-bottom: 1px solid var(--border);
            padding-bottom: 5px;
            margin-top: 30px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary), #005a9e);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        
        .header h1 { color: white; border: none; }
        
        .summary-box {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .risk-low { color: var(--success); }
        .risk-medium { color: var(--warning); }
        .risk-high { color: var(--danger); }
        .risk-critical { color: white; background: var(--danger); padding: 5px 10px; border-radius: 4px; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--bg-secondary);
            font-weight: 600;
        }
        
        tr:hover { background: var(--bg-secondary); }
        
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }
        
        .badge-success { background: #dff6dd; color: var(--success); }
        .badge-danger { background: #fde7e9; color: var(--danger); }
        .badge-warning { background: #fff4ce; color: #8a6914; }
        
        code {
            background: var(--bg-secondary);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', monospace;
        }
        
        .alert {
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
        
        .alert-danger { background: #fde7e9; border-left: 4px solid var(--danger); }
        .alert-warning { background: #fff4ce; border-left: 4px solid var(--warning); }
        .alert-info { background: #cce5ff; border-left: 4px solid var(--primary); }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            color: #605e5c;
            font-size: 0.9em;
        }
        
        @media print {
            body { max-width: none; }
            .no-print { display: none; }
        }
    )";
}

QString ReportGenerator::generateHTMLHeader(const AnalysisReport &report)
{
    QString html;
    html += "<div class=\"header\">\n";
    html += "<h1>" + escapeHtml(reportTitle) + "</h1>\n";
    html += "<p><strong>File:</strong> " + escapeHtml(report.fileName) + "</p>\n";
    html += "<p><strong>Analysis Date:</strong> " + report.analysisTime.toString(Qt::ISODate) + "</p>\n";
    if (!companyLogo.isEmpty()) {
        html += "<img src=\"" + companyLogo + "\" alt=\"Logo\" style=\"max-height: 50px;\">\n";
    }
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateHTMLSummary(const AnalysisReport &report)
{
    QString html;
    html += "<div class=\"summary-box\">\n";
    html += "<h2>Executive Summary</h2>\n";
    
    QString riskClass = "risk-" + report.riskLevel.toLower();
    html += "<p><strong>Risk Level:</strong> <span class=\"" + riskClass + "\">" + escapeHtml(report.riskLevel) + "</span></p>\n";
    
    if (!report.findings.isEmpty()) {
        html += "<h3>Key Findings</h3>\n<ul>\n";
        for (const QString &finding : report.findings) {
            html += "<li>" + escapeHtml(finding) + "</li>\n";
        }
        html += "</ul>\n";
    }
    
    if (!report.recommendations.isEmpty()) {
        html += "<h3>Recommendations</h3>\n<ul>\n";
        for (const QString &rec : report.recommendations) {
            html += "<li>" + escapeHtml(rec) + "</li>\n";
        }
        html += "</ul>\n";
    }
    
    html += "</div>\n";
    return html;
}

QString ReportGenerator::generateHTMLFileInfo(const AnalysisReport &report)
{
    QString html;
    html += "<h2>File Information</h2>\n";
    html += "<table>\n";
    html += "<tr><th>Property</th><th>Value</th></tr>\n";
    html += "<tr><td>File Name</td><td>" + escapeHtml(report.fileName) + "</td></tr>\n";
    html += "<tr><td>File Size</td><td>" + formatBytes(report.fileSize) + "</td></tr>\n";
    html += "<tr><td>MD5</td><td><code>" + escapeHtml(report.md5Hash) + "</code></td></tr>\n";
    html += "<tr><td>SHA-1</td><td><code>" + escapeHtml(report.sha1Hash) + "</code></td></tr>\n";
    html += "<tr><td>SHA-256</td><td><code>" + escapeHtml(report.sha256Hash) + "</code></td></tr>\n";
    html += "<tr><td>PE Type</td><td>" + escapeHtml(report.peType) + "</td></tr>\n";
    html += "<tr><td>Subsystem</td><td>" + escapeHtml(report.subsystem) + "</td></tr>\n";
    html += "<tr><td>Compiler</td><td>" + escapeHtml(report.compiler) + "</td></tr>\n";
    html += "<tr><td>Compile Time</td><td>" + report.compileTime.toString(Qt::ISODate) + "</td></tr>\n";
    html += "<tr><td>Entry Point</td><td><code>" + escapeHtml(report.entryPoint) + "</code></td></tr>\n";
    html += "<tr><td>Image Base</td><td><code>" + escapeHtml(report.imageBase) + "</code></td></tr>\n";
    html += "<tr><td>Sections</td><td>" + QString::number(report.numberOfSections) + "</td></tr>\n";
    html += "<tr><td>Imports</td><td>" + QString::number(report.numberOfImports) + "</td></tr>\n";
    html += "<tr><td>Exports</td><td>" + QString::number(report.numberOfExports) + "</td></tr>\n";
    html += "</table>\n";
    return html;
}

QString ReportGenerator::generateHTMLSecurityInfo(const AnalysisReport &report)
{
    QString html;
    html += "<h2>Security Features</h2>\n";
    html += "<table>\n";
    html += "<tr><th>Feature</th><th>Status</th></tr>\n";
    
    auto statusBadge = [](bool enabled, const QString &onText = "Enabled", const QString &offText = "Disabled") {
        return enabled ? 
            "<span class=\"badge badge-success\">" + onText + "</span>" :
            "<span class=\"badge badge-danger\">" + offText + "</span>";
    };
    
    html += "<tr><td>ASLR (Address Space Layout Randomization)</td><td>" + statusBadge(report.hasASLR) + "</td></tr>\n";
    html += "<tr><td>DEP/NX (Data Execution Prevention)</td><td>" + statusBadge(report.hasDEP) + "</td></tr>\n";
    html += "<tr><td>CFG (Control Flow Guard)</td><td>" + statusBadge(report.hasCFG) + "</td></tr>\n";
    html += "<tr><td>SEH (Structured Exception Handling)</td><td>" + statusBadge(report.hasSEH, "Present", "Not Present") + "</td></tr>\n";
    html += "<tr><td>SafeSEH</td><td>" + statusBadge(report.hasSafeSEH) + "</td></tr>\n";
    html += "<tr><td>High Entropy VA</td><td>" + statusBadge(report.isHighEntropyVA) + "</td></tr>\n";
    html += "<tr><td>Code Signing</td><td>" + statusBadge(report.isSignedBinary, "Signed", "Not Signed") + "</td></tr>\n";
    
    html += "</table>\n";
    return html;
}

QString ReportGenerator::generateHTMLEntropyInfo(const AnalysisReport &report)
{
    QString html;
    html += "<h2>Entropy Analysis</h2>\n";
    html += "<p><strong>Overall Entropy:</strong> " + QString::number(report.overallEntropy, 'f', 4) + "</p>\n";
    
    if (report.isProbablyPacked) {
        html += "<div class=\"alert alert-warning\">⚠️ File appears to be <strong>packed</strong> (high entropy detected)</div>\n";
    }
    if (report.isProbablyEncrypted) {
        html += "<div class=\"alert alert-danger\">⚠️ File contains <strong>encrypted</strong> sections</div>\n";
    }
    
    if (!report.sectionEntropies.isEmpty()) {
        html += "<h3>Section Entropies</h3>\n";
        html += "<table>\n<tr><th>Section</th><th>Entropy</th><th>Status</th></tr>\n";
        for (const auto &pair : report.sectionEntropies) {
            QString status;
            if (pair.second > 7.5) status = "<span class=\"badge badge-danger\">Encrypted</span>";
            else if (pair.second > 6.5) status = "<span class=\"badge badge-warning\">Packed</span>";
            else status = "<span class=\"badge badge-success\">Normal</span>";
            
            html += "<tr><td>" + escapeHtml(pair.first) + "</td><td>" + QString::number(pair.second, 'f', 4) + "</td><td>" + status + "</td></tr>\n";
        }
        html += "</table>\n";
    }
    
    return html;
}

QString ReportGenerator::generateHTMLPackerInfo(const AnalysisReport &report)
{
    if (report.detectedPackers.isEmpty()) return "";
    
    QString html;
    html += "<h2>Packer Detection</h2>\n";
    
    for (const PackerInfo &packer : report.detectedPackers) {
        html += "<div class=\"summary-box\">\n";
        html += "<h3>" + escapeHtml(packer.name) + " " + escapeHtml(packer.version) + "</h3>\n";
        html += "<p><strong>Description:</strong> " + escapeHtml(packer.description) + "</p>\n";
        html += "<p><strong>Confidence:</strong> " + QString::number(packer.confidence * 100, 'f', 1) + "%</p>\n";
        html += "<p><strong>Unpacking Available:</strong> " + QString(packer.canUnpack ? "Yes" : "No") + "</p>\n";
        html += "</div>\n";
    }
    
    return html;
}

QString ReportGenerator::generateHTMLIOCInfo(const AnalysisReport &report)
{
    if (report.extractedIOCs.isEmpty()) return "";
    
    QString html;
    html += "<h2>Indicators of Compromise</h2>\n";
    html += "<table>\n<tr><th>Type</th><th>Value</th><th>Context</th><th>Confidence</th></tr>\n";
    
    for (const IOC &ioc : report.extractedIOCs) {
        html += "<tr><td>" + escapeHtml(IOCExtractor::typeToString(ioc.type)) + "</td>";
        html += "<td><code>" + escapeHtml(ioc.value) + "</code></td>";
        html += "<td>" + escapeHtml(ioc.context) + "</td>";
        html += "<td>" + QString::number(ioc.confidence * 100, 'f', 0) + "%</td></tr>\n";
    }
    
    html += "</table>\n";
    return html;
}

QString ReportGenerator::generateHTMLShellcodeInfo(const AnalysisReport &report)
{
    if (report.shellcodeMatches.isEmpty()) return "";
    
    QString html;
    html += "<h2>Shellcode Detection</h2>\n";
    html += "<div class=\"alert alert-danger\">⚠️ Potential shellcode detected in this file!</div>\n";
    html += "<table>\n<tr><th>Pattern</th><th>Offset</th><th>Size</th><th>Confidence</th><th>Description</th></tr>\n";
    
    for (const ShellcodeMatch &match : report.shellcodeMatches) {
        html += "<tr><td>" + escapeHtml(match.patternName) + "</td>";
        html += "<td><code>0x" + QString::number(match.offset, 16).toUpper() + "</code></td>";
        html += "<td>" + QString::number(match.size) + " bytes</td>";
        html += "<td>" + QString::number(match.confidence * 100, 'f', 0) + "%</td>";
        html += "<td>" + escapeHtml(match.description) + "</td></tr>\n";
    }
    
    html += "</table>\n";
    return html;
}

QString ReportGenerator::generateHTMLYaraInfo(const AnalysisReport &report)
{
    if (report.yaraMatches.isEmpty()) return "";
    
    QString html;
    html += "<h2>YARA Rule Matches</h2>\n";
    
    for (const YaraMatch &match : report.yaraMatches) {
        html += "<div class=\"summary-box\">\n";
        html += "<h3>Rule: " + escapeHtml(match.ruleName) + "</h3>\n";
        if (!match.tags.isEmpty()) {
            html += "<p><strong>Tags:</strong> ";
            for (const QString &tag : match.tags) {
                html += "<span class=\"badge badge-warning\">" + escapeHtml(tag) + "</span> ";
            }
            html += "</p>\n";
        }
        html += "<p><strong>Description:</strong> " + escapeHtml(match.description) + "</p>\n";
        html += "</div>\n";
    }
    
    return html;
}

QString ReportGenerator::generateHTMLAIAnalysis(const AnalysisReport &report)
{
    if (report.aiMalwareAnalysis.isEmpty() && report.aiVulnerabilityAnalysis.isEmpty()) return "";
    
    QString html;
    html += "<h2>AI-Powered Analysis</h2>\n";
    
    if (!report.aiMalwareAnalysis.isEmpty()) {
        html += "<h3>Malware Analysis</h3>\n";
        html += "<div class=\"summary-box\">" + escapeHtml(report.aiMalwareAnalysis).replace("\n", "<br>") + "</div>\n";
    }
    
    if (!report.aiVulnerabilityAnalysis.isEmpty()) {
        html += "<h3>Vulnerability Analysis</h3>\n";
        html += "<div class=\"summary-box\">" + escapeHtml(report.aiVulnerabilityAnalysis).replace("\n", "<br>") + "</div>\n";
    }
    
    return html;
}

QString ReportGenerator::generateHTMLFooter(const AnalysisReport &report)
{
    QString html;
    html += "<div class=\"footer\">\n";
    html += "<p>Generated by <strong>" + escapeHtml(analystName) + "</strong></p>\n";
    html += "<p>Analysis completed on " + report.analysisTime.toString(Qt::RFC2822Date) + "</p>\n";
    html += "<p><em>Modified by 0nsec | Original by hasherezade</em></p>\n";
    html += "</div>\n";
    return html;
}

QString ReportGenerator::riskLevelColor(const QString &level)
{
    QString lower = level.toLower();
    if (lower == "critical") return "#d13438";
    if (lower == "high") return "#f7630c";
    if (lower == "medium") return "#ffc83d";
    if (lower == "low") return "#107c10";
    return "#605e5c";
}

QString ReportGenerator::formatBytes(qint64 bytes)
{
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = bytes;
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    return QString::number(size, 'f', 2) + " " + units[unit];
}

QString ReportGenerator::escapeHtml(const QString &text)
{
    QString result = text;
    result.replace("&", "&amp;");
    result.replace("<", "&lt;");
    result.replace(">", "&gt;");
    result.replace("\"", "&quot;");
    result.replace("'", "&#39;");
    return result;
}

QString ReportGenerator::escapeXml(const QString &text)
{
    return escapeHtml(text);
}

void ReportGenerator::setCustomCSS(const QString &css)
{
    customCSS = css;
}

void ReportGenerator::setCompanyLogo(const QString &logoPath)
{
    companyLogo = logoPath;
}

void ReportGenerator::setReportTitle(const QString &title)
{
    reportTitle = title;
}

void ReportGenerator::setAnalystName(const QString &name)
{
    analystName = name;
}
