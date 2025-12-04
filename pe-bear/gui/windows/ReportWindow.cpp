#include "ReportWindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFileInfo>

ReportWindow::ReportWindow(QWidget *parent)
    : QDockWidget("Report Generator", parent)
    , peHandler(nullptr)
    , generator(new ReportGenerator(this))
    , hasExternalData(false)
{
    setupUI();
    
    connect(generator, &ReportGenerator::reportGenerated, this, &ReportWindow::onReportGenerated);
}

ReportWindow::~ReportWindow()
{
}

void ReportWindow::setupUI()
{
    mainWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // Report settings
    QGroupBox *settingsGroup = new QGroupBox("Report Settings", mainWidget);
    QGridLayout *settingsLayout = new QGridLayout(settingsGroup);
    
    settingsLayout->addWidget(new QLabel("Title:"), 0, 0);
    titleEdit = new QLineEdit("PE Analysis Report");
    settingsLayout->addWidget(titleEdit, 0, 1);
    
    settingsLayout->addWidget(new QLabel("Analyst:"), 1, 0);
    analystEdit = new QLineEdit("PE-bear (0nsec mod)");
    settingsLayout->addWidget(analystEdit, 1, 1);
    
    settingsLayout->addWidget(new QLabel("Format:"), 2, 0);
    formatCombo = new QComboBox();
    formatCombo->addItems({"HTML", "Markdown", "JSON", "XML", "Plain Text", "PDF"});
    settingsLayout->addWidget(formatCombo, 2, 1);
    
    mainLayout->addWidget(settingsGroup);

    // Include sections
    QGroupBox *includeGroup = new QGroupBox("Include Sections", mainWidget);
    QGridLayout *includeLayout = new QGridLayout(includeGroup);
    
    includeFileInfo = new QCheckBox("File Information");
    includeFileInfo->setChecked(true);
    includeLayout->addWidget(includeFileInfo, 0, 0);
    
    includeSecurity = new QCheckBox("Security Features");
    includeSecurity->setChecked(true);
    includeLayout->addWidget(includeSecurity, 0, 1);
    
    includeEntropy = new QCheckBox("Entropy Analysis");
    includeEntropy->setChecked(true);
    includeLayout->addWidget(includeEntropy, 1, 0);
    
    includePackers = new QCheckBox("Packer Detection");
    includePackers->setChecked(true);
    includeLayout->addWidget(includePackers, 1, 1);
    
    includeIOCs = new QCheckBox("IOC Extraction");
    includeIOCs->setChecked(true);
    includeLayout->addWidget(includeIOCs, 2, 0);
    
    includeShellcode = new QCheckBox("Shellcode Detection");
    includeShellcode->setChecked(true);
    includeLayout->addWidget(includeShellcode, 2, 1);
    
    includeYara = new QCheckBox("YARA Matches");
    includeYara->setChecked(true);
    includeLayout->addWidget(includeYara, 3, 0);
    
    includeAI = new QCheckBox("AI Analysis");
    includeAI->setChecked(true);
    includeLayout->addWidget(includeAI, 3, 1);
    
    mainLayout->addWidget(includeGroup);

    // Progress
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    // Preview
    QGroupBox *previewGroup = new QGroupBox("Preview", mainWidget);
    QVBoxLayout *previewLayout = new QVBoxLayout(previewGroup);
    
    previewText = new QTextEdit();
    previewText->setReadOnly(true);
    previewText->setStyleSheet("background-color: #1e1e1e; font-family: 'Consolas', monospace;");
    previewText->setPlaceholderText("Click 'Preview' to see report preview...");
    previewLayout->addWidget(previewText);
    
    mainLayout->addWidget(previewGroup, 1);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    previewButton = new QPushButton("Preview");
    connect(previewButton, &QPushButton::clicked, this, &ReportWindow::previewReport);
    buttonLayout->addWidget(previewButton);
    
    generateButton = new QPushButton("Generate Report");
    generateButton->setStyleSheet("QPushButton { background-color: #0078d4; color: white; padding: 8px 20px; }");
    connect(generateButton, &QPushButton::clicked, this, &ReportWindow::generateReport);
    buttonLayout->addWidget(generateButton);
    
    buttonLayout->addStretch();
    
    statusLabel = new QLabel("Ready");
    statusLabel->setStyleSheet("color: #888;");
    buttonLayout->addWidget(statusLabel);
    
    mainLayout->addLayout(buttonLayout);

    setWidget(mainWidget);
    setMinimumWidth(450);
}

void ReportWindow::setPeHandler(PeHandler *handler)
{
    peHandler = handler;
    generateButton->setEnabled(handler != nullptr);
    previewButton->setEnabled(handler != nullptr);
}

void ReportWindow::setAnalysisResults(const AnalysisReport &report)
{
    currentReport = report;
    hasExternalData = true;
}

AnalysisReport ReportWindow::gatherReportData()
{
    AnalysisReport report;
    
    if (!peHandler || !peHandler->getPe()) {
        return report;
    }
    
    PEFile *pe = peHandler->getPe();
    
    // File info
    report.fileName = QFileInfo(peHandler->getFullName()).fileName();
    report.filePath = peHandler->getFullName();
    report.fileSize = pe->getRawSize();
    report.analysisTime = QDateTime::currentDateTime();
    
    // Calculate hashes
    QByteArray fileData = QByteArray::fromRawData(
        reinterpret_cast<const char*>(pe->getContent()),
        static_cast<int>(pe->getRawSize())
    );
    
    report.md5Hash = QCryptographicHash::hash(fileData, QCryptographicHash::Md5).toHex();
    report.sha1Hash = QCryptographicHash::hash(fileData, QCryptographicHash::Sha1).toHex();
    report.sha256Hash = QCryptographicHash::hash(fileData, QCryptographicHash::Sha256).toHex();
    
    // PE info
    report.peType = pe->isBit64() ? "64-bit" : "32-bit";
    report.entryPoint = QString("0x%1").arg(pe->getEntryPoint(), 0, 16).toUpper();
    
    // Sections count
    report.numberOfSections = pe->getSectionsCount(false);
    
    // Security features (simplified - would need deeper PE analysis)
    // These would be populated from actual PE header analysis
    report.hasASLR = false;
    report.hasDEP = false;
    report.hasCFG = false;
    report.hasSEH = true;
    report.hasSafeSEH = false;
    report.isHighEntropyVA = false;
    report.isSignedBinary = false;
    
    // Default risk level
    report.riskLevel = "Medium";
    
    // If we have external data from other analysis windows, merge it
    if (hasExternalData) {
        if (!currentReport.extractedIOCs.isEmpty()) {
            report.extractedIOCs = currentReport.extractedIOCs;
        }
        if (!currentReport.shellcodeMatches.isEmpty()) {
            report.shellcodeMatches = currentReport.shellcodeMatches;
        }
        if (!currentReport.detectedPackers.isEmpty()) {
            report.detectedPackers = currentReport.detectedPackers;
        }
        if (!currentReport.sectionEntropies.isEmpty()) {
            report.sectionEntropies = currentReport.sectionEntropies;
            report.overallEntropy = currentReport.overallEntropy;
            report.isProbablyPacked = currentReport.isProbablyPacked;
            report.isProbablyEncrypted = currentReport.isProbablyEncrypted;
        }
        if (!currentReport.aiMalwareAnalysis.isEmpty()) {
            report.aiMalwareAnalysis = currentReport.aiMalwareAnalysis;
        }
        if (!currentReport.aiVulnerabilityAnalysis.isEmpty()) {
            report.aiVulnerabilityAnalysis = currentReport.aiVulnerabilityAnalysis;
        }
    }
    
    // Generate findings based on analysis
    if (report.isProbablyPacked) {
        report.findings.append("File appears to be packed (high entropy)");
    }
    if (report.isProbablyEncrypted) {
        report.findings.append("File contains encrypted sections");
    }
    if (!report.shellcodeMatches.isEmpty()) {
        report.findings.append(QString("Detected %1 potential shellcode patterns").arg(report.shellcodeMatches.size()));
        report.riskLevel = "High";
    }
    if (!report.detectedPackers.isEmpty()) {
        report.findings.append(QString("Detected packer: %1").arg(report.detectedPackers.first().name));
    }
    
    // Recommendations
    if (!report.hasASLR) {
        report.recommendations.append("Enable ASLR for better security");
    }
    if (!report.hasDEP) {
        report.recommendations.append("Enable DEP/NX bit");
    }
    if (!report.isSignedBinary) {
        report.recommendations.append("Consider code signing the binary");
    }
    
    return report;
}

void ReportWindow::previewReport()
{
    generator->setReportTitle(titleEdit->text());
    generator->setAnalystName(analystEdit->text());
    
    AnalysisReport report = gatherReportData();
    
    // Generate markdown preview
    QString preview = generator->generateMarkdown(report);
    previewText->setPlainText(preview);
    
    statusLabel->setText("Preview generated");
}

void ReportWindow::generateReport()
{
    QString format = formatCombo->currentText();
    QString filter;
    QString defaultName;
    ReportFormat reportFormat;
    
    if (format == "HTML") {
        filter = "HTML Files (*.html)";
        defaultName = "report.html";
        reportFormat = ReportFormat::HTML;
    } else if (format == "Markdown") {
        filter = "Markdown Files (*.md)";
        defaultName = "report.md";
        reportFormat = ReportFormat::Markdown;
    } else if (format == "JSON") {
        filter = "JSON Files (*.json)";
        defaultName = "report.json";
        reportFormat = ReportFormat::JSON;
    } else if (format == "XML") {
        filter = "XML Files (*.xml)";
        defaultName = "report.xml";
        reportFormat = ReportFormat::XML;
    } else if (format == "Plain Text") {
        filter = "Text Files (*.txt)";
        defaultName = "report.txt";
        reportFormat = ReportFormat::PlainText;
    } else {
        filter = "PDF Files (*.pdf)";
        defaultName = "report.pdf";
        reportFormat = ReportFormat::PDF;
    }
    
    QString fileName = QFileDialog::getSaveFileName(this, "Save Report", defaultName, filter);
    if (fileName.isEmpty()) return;
    
    progressBar->setVisible(true);
    progressBar->setValue(0);
    statusLabel->setText("Generating report...");
    generateButton->setEnabled(false);
    
    generator->setReportTitle(titleEdit->text());
    generator->setAnalystName(analystEdit->text());
    
    AnalysisReport report = gatherReportData();
    
    progressBar->setValue(50);
    
    if (generator->generateReport(report, fileName, reportFormat)) {
        progressBar->setValue(100);
    }
}

void ReportWindow::onReportGenerated(const QString &path)
{
    progressBar->setVisible(false);
    generateButton->setEnabled(true);
    statusLabel->setText("Report saved!");
    
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Report Generated",
        QString("Report saved to:\n%1\n\nOpen the report?").arg(path),
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::Yes) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    }
}
