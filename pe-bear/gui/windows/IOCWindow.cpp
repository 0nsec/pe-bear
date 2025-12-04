#include "IOCWindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>

IOCWindow::IOCWindow(QWidget *parent)
    : QDockWidget("IOC Extractor", parent)
    , peHandler(nullptr)
    , extractor(new IOCExtractor(this))
{
    setupUI();
    
    connect(extractor, &IOCExtractor::extractionComplete, this, &IOCWindow::onExtractionComplete);
}

IOCWindow::~IOCWindow()
{
}

void IOCWindow::setupUI()
{
    mainWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // Controls
    QGroupBox *controlsGroup = new QGroupBox("Extraction", mainWidget);
    QHBoxLayout *controlsLayout = new QHBoxLayout(controlsGroup);
    
    extractButton = new QPushButton("Extract IOCs");
    extractButton->setStyleSheet("QPushButton { background-color: #0078d4; color: white; padding: 5px 15px; }");
    connect(extractButton, &QPushButton::clicked, this, &IOCWindow::extractIOCs);
    controlsLayout->addWidget(extractButton);
    
    controlsLayout->addStretch();
    
    statusLabel = new QLabel("Ready");
    statusLabel->setStyleSheet("color: #888;");
    controlsLayout->addWidget(statusLabel);
    
    mainLayout->addWidget(controlsGroup);

    // Progress bar
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    // Filters
    QGroupBox *filterGroup = new QGroupBox("Filters", mainWidget);
    QVBoxLayout *filterLayout = new QVBoxLayout(filterGroup);
    
    QHBoxLayout *searchLayout = new QHBoxLayout();
    searchLayout->addWidget(new QLabel("Search:"));
    filterEdit = new QLineEdit();
    filterEdit->setPlaceholderText("Filter IOCs...");
    connect(filterEdit, &QLineEdit::textChanged, this, &IOCWindow::filterResults);
    searchLayout->addWidget(filterEdit);
    filterLayout->addLayout(searchLayout);
    
    QHBoxLayout *checkLayout = new QHBoxLayout();
    showURLs = new QCheckBox("URLs");
    showURLs->setChecked(true);
    connect(showURLs, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(showURLs);
    
    showIPs = new QCheckBox("IPs");
    showIPs->setChecked(true);
    connect(showIPs, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(showIPs);
    
    showDomains = new QCheckBox("Domains");
    showDomains->setChecked(true);
    connect(showDomains, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(showDomains);
    
    showEmails = new QCheckBox("Emails");
    showEmails->setChecked(true);
    connect(showEmails, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(showEmails);
    
    showPaths = new QCheckBox("Paths");
    showPaths->setChecked(true);
    connect(showPaths, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(showPaths);
    
    showHashes = new QCheckBox("Hashes");
    showHashes->setChecked(true);
    connect(showHashes, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(showHashes);
    
    suspiciousOnly = new QCheckBox("Suspicious Only");
    suspiciousOnly->setStyleSheet("color: #ff4444;");
    connect(suspiciousOnly, &QCheckBox::toggled, [this](bool) { filterResults(filterEdit->text()); });
    checkLayout->addWidget(suspiciousOnly);
    
    checkLayout->addStretch();
    filterLayout->addLayout(checkLayout);
    
    mainLayout->addWidget(filterGroup);

    // Results table
    iocTable = new QTableWidget();
    iocTable->setColumnCount(5);
    iocTable->setHorizontalHeaderLabels({"Type", "Value", "Defanged", "Suspicious", "Context"});
    iocTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    iocTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    iocTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    iocTable->setAlternatingRowColors(true);
    iocTable->setStyleSheet("QTableWidget { background-color: #1e1e1e; } "
                            "QTableWidget::item:alternate { background-color: #252526; }");
    mainLayout->addWidget(iocTable, 1);

    // Export controls
    QHBoxLayout *exportLayout = new QHBoxLayout();
    
    copyButton = new QPushButton("Copy Selected");
    copyButton->setEnabled(false);
    connect(copyButton, &QPushButton::clicked, this, &IOCWindow::copySelected);
    exportLayout->addWidget(copyButton);
    
    exportFormatCombo = new QComboBox();
    exportFormatCombo->addItems({"Text", "CSV", "JSON", "STIX 2.1"});
    exportLayout->addWidget(exportFormatCombo);
    
    exportButton = new QPushButton("Export");
    exportButton->setEnabled(false);
    connect(exportButton, &QPushButton::clicked, this, &IOCWindow::exportResults);
    exportLayout->addWidget(exportButton);
    
    exportLayout->addStretch();
    mainLayout->addLayout(exportLayout);

    setWidget(mainWidget);
    setMinimumWidth(500);
    
    connect(iocTable, &QTableWidget::itemSelectionChanged, [this]() {
        copyButton->setEnabled(iocTable->selectedItems().count() > 0);
    });
}

void IOCWindow::setPeHandler(PeHandler *handler)
{
    peHandler = handler;
    extractButton->setEnabled(handler != nullptr);
}

void IOCWindow::extractIOCs()
{
    if (!peHandler || !peHandler->getPe()) {
        QMessageBox::warning(this, "Error", "No PE file loaded");
        return;
    }

    extractButton->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setValue(0);
    statusLabel->setText("Extracting...");

    // Get file data
    PEFile *pe = peHandler->getPe();
    QByteArray fileData = QByteArray::fromRawData(
        reinterpret_cast<const char*>(pe->getContent()), 
        static_cast<int>(pe->getRawSize())
    );

    progressBar->setValue(30);
    
    // Extract IOCs
    allIOCs = extractor->extractFromBinary(fileData);
    
    progressBar->setValue(100);
    onExtractionComplete(allIOCs);
}

void IOCWindow::onExtractionComplete(const QList<IOC> &iocs)
{
    allIOCs = iocs;
    populateTable(iocs);
    
    extractButton->setEnabled(true);
    progressBar->setVisible(false);
    exportButton->setEnabled(!iocs.isEmpty());
    
    statusLabel->setText(QString("%1 IOCs found").arg(iocs.size()));
}

void IOCWindow::populateTable(const QList<IOC> &iocs)
{
    iocTable->setRowCount(0);
    iocTable->setRowCount(iocs.size());
    
    for (int i = 0; i < iocs.size(); i++) {
        const IOC &ioc = iocs[i];
        
        QTableWidgetItem *typeItem = new QTableWidgetItem(IOCExtractor::typeToString(ioc.type));
        QTableWidgetItem *valueItem = new QTableWidgetItem(ioc.value);
        QTableWidgetItem *defangedItem = new QTableWidgetItem(ioc.defanged);
        QTableWidgetItem *suspiciousItem = new QTableWidgetItem(ioc.isSuspicious ? "⚠️ Yes" : "No");
        QTableWidgetItem *contextItem = new QTableWidgetItem(ioc.context);
        
        if (ioc.isSuspicious) {
            typeItem->setBackground(QColor(100, 50, 50));
            valueItem->setBackground(QColor(100, 50, 50));
            defangedItem->setBackground(QColor(100, 50, 50));
            suspiciousItem->setBackground(QColor(100, 50, 50));
            contextItem->setBackground(QColor(100, 50, 50));
        }
        
        iocTable->setItem(i, 0, typeItem);
        iocTable->setItem(i, 1, valueItem);
        iocTable->setItem(i, 2, defangedItem);
        iocTable->setItem(i, 3, suspiciousItem);
        iocTable->setItem(i, 4, contextItem);
    }
}

void IOCWindow::filterResults(const QString &text)
{
    QList<IOC> filtered;
    
    for (const IOC &ioc : allIOCs) {
        // Type filter
        bool typeMatch = false;
        switch (ioc.type) {
            case IOC::URL: typeMatch = showURLs->isChecked(); break;
            case IOC::IP_ADDRESS: typeMatch = showIPs->isChecked(); break;
            case IOC::DOMAIN: typeMatch = showDomains->isChecked(); break;
            case IOC::EMAIL: typeMatch = showEmails->isChecked(); break;
            case IOC::FILE_PATH: typeMatch = showPaths->isChecked(); break;
            case IOC::HASH_MD5:
            case IOC::HASH_SHA1:
            case IOC::HASH_SHA256: typeMatch = showHashes->isChecked(); break;
            default: typeMatch = true;
        }
        
        if (!typeMatch) continue;
        
        // Suspicious filter
        if (suspiciousOnly->isChecked() && !ioc.isSuspicious) continue;
        
        // Text filter
        if (!text.isEmpty()) {
            if (!ioc.value.contains(text, Qt::CaseInsensitive) &&
                !ioc.defanged.contains(text, Qt::CaseInsensitive)) {
                continue;
            }
        }
        
        filtered.append(ioc);
    }
    
    populateTable(filtered);
    statusLabel->setText(QString("Showing %1 of %2 IOCs").arg(filtered.size()).arg(allIOCs.size()));
}

void IOCWindow::copySelected()
{
    QStringList values;
    for (QTableWidgetItem *item : iocTable->selectedItems()) {
        if (item->column() == 2) { // Defanged column
            values.append(item->text());
        }
    }
    
    if (!values.isEmpty()) {
        QApplication::clipboard()->setText(values.join("\n"));
        statusLabel->setText("Copied to clipboard");
    }
}

void IOCWindow::exportResults()
{
    if (allIOCs.isEmpty()) return;
    
    QString format = exportFormatCombo->currentText();
    QString filter;
    QString defaultExt;
    
    if (format == "Text") {
        filter = "Text Files (*.txt)";
        defaultExt = ".txt";
    } else if (format == "CSV") {
        filter = "CSV Files (*.csv)";
        defaultExt = ".csv";
    } else if (format == "JSON") {
        filter = "JSON Files (*.json)";
        defaultExt = ".json";
    } else {
        filter = "JSON Files (*.json)";
        defaultExt = "_stix.json";
    }
    
    QString fileName = QFileDialog::getSaveFileName(this, "Export IOCs", 
        "iocs" + defaultExt, filter);
    
    if (fileName.isEmpty()) return;
    
    QString content;
    if (format == "Text") {
        content = extractor->exportToText(allIOCs);
    } else if (format == "CSV") {
        content = extractor->exportToCSV(allIOCs);
    } else if (format == "JSON") {
        content = extractor->exportToJSON(allIOCs);
    } else {
        content = extractor->exportToSTIX(allIOCs);
    }
    
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream << content;
        file.close();
        QMessageBox::information(this, "Success", "IOCs exported successfully");
    } else {
        QMessageBox::warning(this, "Error", "Failed to export IOCs");
    }
}
