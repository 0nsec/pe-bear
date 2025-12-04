#include "ShellcodeWindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QSplitter>

ShellcodeWindow::ShellcodeWindow(QWidget *parent)
    : QDockWidget("Shellcode Detector", parent)
    , peHandler(nullptr)
    , detector(new ShellcodeDetector(this))
{
    setupUI();
    
    connect(detector, &ShellcodeDetector::detectionComplete, this, &ShellcodeWindow::onDetectionComplete);
}

ShellcodeWindow::~ShellcodeWindow()
{
}

void ShellcodeWindow::setupUI()
{
    mainWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // Controls
    QGroupBox *controlsGroup = new QGroupBox("Detection", mainWidget);
    QHBoxLayout *controlsLayout = new QHBoxLayout(controlsGroup);
    
    scanButton = new QPushButton("Scan for Shellcode");
    scanButton->setStyleSheet("QPushButton { background-color: #d41a1a; color: white; padding: 5px 15px; }");
    connect(scanButton, &QPushButton::clicked, this, &ShellcodeWindow::scanForShellcode);
    controlsLayout->addWidget(scanButton);
    
    controlsLayout->addStretch();
    
    statusLabel = new QLabel("Ready");
    statusLabel->setStyleSheet("color: #888;");
    controlsLayout->addWidget(statusLabel);
    
    mainLayout->addWidget(controlsGroup);

    // Progress bar
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    // Warning banner
    QLabel *warningLabel = new QLabel("⚠️ This tool detects common shellcode patterns. False positives may occur.");
    warningLabel->setStyleSheet("background-color: #4a3500; color: #ffa500; padding: 8px; border-radius: 4px;");
    mainLayout->addWidget(warningLabel);

    // Splitter for table and details
    QSplitter *splitter = new QSplitter(Qt::Vertical);

    // Results table
    QGroupBox *resultsGroup = new QGroupBox("Detection Results");
    QVBoxLayout *resultsLayout = new QVBoxLayout(resultsGroup);
    
    resultsTable = new QTableWidget();
    resultsTable->setColumnCount(6);
    resultsTable->setHorizontalHeaderLabels({"Pattern", "Offset", "Size", "Platform", "Architecture", "Confidence"});
    resultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable->setAlternatingRowColors(true);
    resultsTable->setStyleSheet("QTableWidget { background-color: #1e1e1e; } "
                                "QTableWidget::item:alternate { background-color: #252526; }");
    connect(resultsTable, &QTableWidget::cellClicked, this, &ShellcodeWindow::showDetails);
    resultsLayout->addWidget(resultsTable);
    
    splitter->addWidget(resultsGroup);

    // Details panel
    QGroupBox *detailsGroup = new QGroupBox("Details");
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsGroup);
    
    detailsView = new QTextEdit();
    detailsView->setReadOnly(true);
    detailsView->setMaximumHeight(80);
    detailsView->setStyleSheet("background-color: #1e1e1e; font-family: 'Consolas', monospace;");
    detailsLayout->addWidget(detailsView);
    
    QLabel *hexLabel = new QLabel("Hex Dump:");
    hexLabel->setStyleSheet("font-weight: bold;");
    detailsLayout->addWidget(hexLabel);
    
    hexView = new QTextEdit();
    hexView->setReadOnly(true);
    hexView->setStyleSheet("background-color: #0d0d0d; font-family: 'Consolas', monospace; color: #00ff00;");
    detailsLayout->addWidget(hexView);
    
    splitter->addWidget(detailsGroup);
    
    splitter->setSizes({300, 200});
    mainLayout->addWidget(splitter, 1);

    // Export button
    QHBoxLayout *exportLayout = new QHBoxLayout();
    
    exportButton = new QPushButton("Export Selected Shellcode");
    exportButton->setEnabled(false);
    connect(exportButton, &QPushButton::clicked, this, &ShellcodeWindow::exportShellcode);
    exportLayout->addWidget(exportButton);
    
    exportLayout->addStretch();
    mainLayout->addLayout(exportLayout);

    setWidget(mainWidget);
    setMinimumWidth(500);
}

void ShellcodeWindow::setPeHandler(PeHandler *handler)
{
    peHandler = handler;
    scanButton->setEnabled(handler != nullptr);
}

void ShellcodeWindow::scanForShellcode()
{
    if (!peHandler || !peHandler->getPe()) {
        QMessageBox::warning(this, "Error", "No PE file loaded");
        return;
    }

    scanButton->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setValue(0);
    statusLabel->setText("Scanning...");
    detailsView->clear();
    hexView->clear();

    // Get file data
    PEFile *pe = peHandler->getPe();
    QByteArray fileData = QByteArray::fromRawData(
        reinterpret_cast<const char*>(pe->getContent()), 
        static_cast<int>(pe->getRawSize())
    );

    progressBar->setValue(30);
    
    // Scan for shellcode
    allMatches = detector->scanForShellcode(fileData);
    
    progressBar->setValue(100);
    onDetectionComplete(allMatches);
}

void ShellcodeWindow::onDetectionComplete(const QList<ShellcodeMatch> &matches)
{
    allMatches = matches;
    populateTable(matches);
    
    scanButton->setEnabled(true);
    progressBar->setVisible(false);
    exportButton->setEnabled(!matches.isEmpty());
    
    if (matches.isEmpty()) {
        statusLabel->setText("No shellcode detected");
        statusLabel->setStyleSheet("color: #44ff44;");
    } else {
        statusLabel->setText(QString("⚠️ %1 potential shellcode patterns found!").arg(matches.size()));
        statusLabel->setStyleSheet("color: #ff4444; font-weight: bold;");
    }
}

void ShellcodeWindow::populateTable(const QList<ShellcodeMatch> &matches)
{
    resultsTable->setRowCount(0);
    resultsTable->setRowCount(matches.size());
    
    for (int i = 0; i < matches.size(); i++) {
        const ShellcodeMatch &match = matches[i];
        
        QTableWidgetItem *patternItem = new QTableWidgetItem(match.patternName);
        QTableWidgetItem *offsetItem = new QTableWidgetItem(QString("0x%1").arg(match.offset, 8, 16, QChar('0')).toUpper());
        QTableWidgetItem *sizeItem = new QTableWidgetItem(QString::number(match.size) + " bytes");
        QTableWidgetItem *platformItem = new QTableWidgetItem(match.platform);
        QTableWidgetItem *archItem = new QTableWidgetItem(match.architecture);
        QTableWidgetItem *confItem = new QTableWidgetItem(QString("%1%").arg(match.confidence * 100, 0, 'f', 0));
        
        // Color code by confidence
        QColor bgColor;
        if (match.confidence >= 0.8) {
            bgColor = QColor(100, 30, 30);
        } else if (match.confidence >= 0.5) {
            bgColor = QColor(100, 70, 30);
        } else {
            bgColor = QColor(70, 70, 30);
        }
        
        patternItem->setBackground(bgColor);
        offsetItem->setBackground(bgColor);
        sizeItem->setBackground(bgColor);
        platformItem->setBackground(bgColor);
        archItem->setBackground(bgColor);
        confItem->setBackground(bgColor);
        
        resultsTable->setItem(i, 0, patternItem);
        resultsTable->setItem(i, 1, offsetItem);
        resultsTable->setItem(i, 2, sizeItem);
        resultsTable->setItem(i, 3, platformItem);
        resultsTable->setItem(i, 4, archItem);
        resultsTable->setItem(i, 5, confItem);
    }
}

void ShellcodeWindow::showDetails(int row, int column)
{
    Q_UNUSED(column);
    
    if (row < 0 || row >= allMatches.size()) return;
    
    const ShellcodeMatch &match = allMatches[row];
    
    // Show details
    QString details;
    details += QString("<b>Pattern:</b> %1<br>").arg(match.patternName);
    details += QString("<b>Description:</b> %1<br>").arg(match.description);
    details += QString("<b>Offset:</b> 0x%1<br>").arg(match.offset, 8, 16, QChar('0')).toUpper();
    details += QString("<b>Size:</b> %1 bytes<br>").arg(match.size);
    details += QString("<b>Platform:</b> %1 / %2<br>").arg(match.platform).arg(match.architecture);
    details += QString("<b>Confidence:</b> %1%").arg(match.confidence * 100, 0, 'f', 1);
    
    detailsView->setHtml(details);
    
    // Show hex dump
    QString hexDump;
    int bytesPerLine = 16;
    for (int i = 0; i < match.data.size(); i++) {
        if (i > 0 && i % bytesPerLine == 0) {
            hexDump += "\n";
        }
        hexDump += QString("%1 ").arg(static_cast<unsigned char>(match.data[i]), 2, 16, QChar('0')).toUpper();
    }
    hexView->setPlainText(hexDump);
}

void ShellcodeWindow::exportShellcode()
{
    int row = resultsTable->currentRow();
    if (row < 0 || row >= allMatches.size()) {
        QMessageBox::warning(this, "Error", "Please select a shellcode entry to export");
        return;
    }
    
    const ShellcodeMatch &match = allMatches[row];
    
    QString fileName = QFileDialog::getSaveFileName(this, "Export Shellcode",
        QString("shellcode_0x%1.bin").arg(match.offset, 8, 16, QChar('0')),
        "Binary Files (*.bin);;All Files (*)");
    
    if (fileName.isEmpty()) return;
    
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(match.data);
        file.close();
        QMessageBox::information(this, "Success", 
            QString("Shellcode exported (%1 bytes)").arg(match.data.size()));
    } else {
        QMessageBox::warning(this, "Error", "Failed to export shellcode");
    }
}
