#include "EntropyWindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QGridLayout>
#include <QTableWidget>
#include <QHeaderView>

EntropyWindow::EntropyWindow(QWidget *parent)
    : QDockWidget("Entropy Analysis", parent)
    , peHandler(nullptr)
    , analyzer(new EntropyAnalyzer(this))
{
    setupUI();
    
    connect(analyzer, &EntropyAnalyzer::analysisComplete, this, &EntropyWindow::onAnalysisComplete);
}

EntropyWindow::~EntropyWindow()
{
}

void EntropyWindow::setupUI()
{
    mainWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // Controls group
    QGroupBox *controlsGroup = new QGroupBox("Analysis Settings", mainWidget);
    QHBoxLayout *controlsLayout = new QHBoxLayout(controlsGroup);
    
    controlsLayout->addWidget(new QLabel("Block Size:"));
    blockSizeSpinBox = new QSpinBox();
    blockSizeSpinBox->setRange(64, 4096);
    blockSizeSpinBox->setValue(256);
    blockSizeSpinBox->setSingleStep(64);
    controlsLayout->addWidget(blockSizeSpinBox);
    
    controlsLayout->addWidget(new QLabel("View:"));
    visualizationCombo = new QComboBox();
    visualizationCombo->addItems({"Heatmap", "Graph", "Both"});
    visualizationCombo->setCurrentIndex(2);
    controlsLayout->addWidget(visualizationCombo);
    
    controlsLayout->addStretch();
    
    analyzeButton = new QPushButton("Analyze");
    analyzeButton->setStyleSheet("QPushButton { background-color: #0078d4; color: white; padding: 5px 15px; }");
    connect(analyzeButton, &QPushButton::clicked, this, &EntropyWindow::analyzeEntropy);
    controlsLayout->addWidget(analyzeButton);
    
    mainLayout->addWidget(controlsGroup);

    // Overall entropy display
    QGroupBox *summaryGroup = new QGroupBox("Summary", mainWidget);
    QHBoxLayout *summaryLayout = new QHBoxLayout(summaryGroup);
    
    overallEntropyLabel = new QLabel("Overall Entropy: --");
    overallEntropyLabel->setStyleSheet("font-size: 14px; font-weight: bold;");
    summaryLayout->addWidget(overallEntropyLabel);
    
    statusLabel = new QLabel("");
    statusLabel->setStyleSheet("color: #888;");
    summaryLayout->addWidget(statusLabel);
    summaryLayout->addStretch();
    
    mainLayout->addWidget(summaryGroup);

    // Progress bar
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    // Visualization area
    QGroupBox *visualGroup = new QGroupBox("Visualization", mainWidget);
    QVBoxLayout *visualLayout = new QVBoxLayout(visualGroup);
    
    // Heatmap
    QLabel *heatmapTitle = new QLabel("Entropy Heatmap:");
    heatmapTitle->setStyleSheet("font-weight: bold;");
    visualLayout->addWidget(heatmapTitle);
    
    heatmapScrollArea = new QScrollArea();
    heatmapScrollArea->setWidgetResizable(true);
    heatmapScrollArea->setMinimumHeight(80);
    heatmapLabel = new QLabel();
    heatmapLabel->setAlignment(Qt::AlignCenter);
    heatmapLabel->setText("No data - click Analyze");
    heatmapLabel->setStyleSheet("background-color: #1e1e1e; color: #888; padding: 20px;");
    heatmapScrollArea->setWidget(heatmapLabel);
    visualLayout->addWidget(heatmapScrollArea);
    
    // Graph
    QLabel *graphTitle = new QLabel("Entropy Graph:");
    graphTitle->setStyleSheet("font-weight: bold;");
    visualLayout->addWidget(graphTitle);
    
    graphScrollArea = new QScrollArea();
    graphScrollArea->setWidgetResizable(true);
    graphScrollArea->setMinimumHeight(200);
    graphLabel = new QLabel();
    graphLabel->setAlignment(Qt::AlignCenter);
    graphLabel->setText("No data - click Analyze");
    graphLabel->setStyleSheet("background-color: #1e1e1e; color: #888; padding: 20px;");
    graphScrollArea->setWidget(graphLabel);
    visualLayout->addWidget(graphScrollArea);
    
    mainLayout->addWidget(visualGroup, 1);

    // Export buttons
    QHBoxLayout *exportLayout = new QHBoxLayout();
    exportHeatmapButton = new QPushButton("Export Heatmap");
    exportHeatmapButton->setEnabled(false);
    connect(exportHeatmapButton, &QPushButton::clicked, this, &EntropyWindow::exportHeatmap);
    exportLayout->addWidget(exportHeatmapButton);
    
    exportGraphButton = new QPushButton("Export Graph");
    exportGraphButton->setEnabled(false);
    connect(exportGraphButton, &QPushButton::clicked, this, &EntropyWindow::exportGraph);
    exportLayout->addWidget(exportGraphButton);
    
    exportLayout->addStretch();
    mainLayout->addLayout(exportLayout);

    // Legend
    QGroupBox *legendGroup = new QGroupBox("Legend", mainWidget);
    QHBoxLayout *legendLayout = new QHBoxLayout(legendGroup);
    
    QLabel *lowLabel = new QLabel("Low (0-3)");
    lowLabel->setStyleSheet("background-color: #00ff00; color: black; padding: 3px 8px;");
    legendLayout->addWidget(lowLabel);
    
    QLabel *normalLabel = new QLabel("Normal (3-6.5)");
    normalLabel->setStyleSheet("background-color: #ffff00; color: black; padding: 3px 8px;");
    legendLayout->addWidget(normalLabel);
    
    QLabel *packedLabel = new QLabel("Packed (6.5-7.5)");
    packedLabel->setStyleSheet("background-color: #ffa500; color: black; padding: 3px 8px;");
    legendLayout->addWidget(packedLabel);
    
    QLabel *encryptedLabel = new QLabel("Encrypted (7.5-8)");
    encryptedLabel->setStyleSheet("background-color: #ff0000; color: white; padding: 3px 8px;");
    legendLayout->addWidget(encryptedLabel);
    
    legendLayout->addStretch();
    mainLayout->addWidget(legendGroup);

    setWidget(mainWidget);
    setMinimumWidth(400);
}

void EntropyWindow::setPeHandler(PeHandler *handler)
{
    peHandler = handler;
    analyzeButton->setEnabled(handler != nullptr);
}

void EntropyWindow::analyzeEntropy()
{
    if (!peHandler || !peHandler->getPe()) {
        QMessageBox::warning(this, "Error", "No PE file loaded");
        return;
    }

    analyzeButton->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setValue(0);
    statusLabel->setText("Analyzing...");

    // Get file data
    PEFile *pe = peHandler->getPe();
    QByteArray fileData = QByteArray::fromRawData(
        reinterpret_cast<const char*>(pe->getContent()), 
        static_cast<int>(pe->getRawSize())
    );

    // Run analysis
    size_t blockSize = static_cast<size_t>(blockSizeSpinBox->value());
    lastResults = analyzer->analyzeFile(fileData, blockSize);
    
    progressBar->setValue(100);
    onAnalysisComplete(lastResults);
}

void EntropyWindow::onAnalysisComplete(const QList<EntropyBlock> &blocks)
{
    lastResults = blocks;
    updateDisplay(blocks);
    
    analyzeButton->setEnabled(true);
    progressBar->setVisible(false);
    
    exportHeatmapButton->setEnabled(!blocks.isEmpty());
    exportGraphButton->setEnabled(!blocks.isEmpty());
}

void EntropyWindow::updateDisplay(const QList<EntropyBlock> &blocks)
{
    if (blocks.isEmpty()) {
        statusLabel->setText("No data");
        return;
    }

    // Calculate overall entropy
    double totalEntropy = 0;
    size_t totalSize = 0;
    bool isPacked = false;
    bool isEncrypted = false;

    for (const EntropyBlock &block : blocks) {
        totalEntropy += block.entropy * block.size;
        totalSize += block.size;
        if (block.isPacked) isPacked = true;
        if (block.isEncrypted) isEncrypted = true;
    }

    double overallEntropy = totalSize > 0 ? totalEntropy / totalSize : 0;
    
    QString entropyText = QString("Overall Entropy: %1").arg(overallEntropy, 0, 'f', 4);
    if (isEncrypted) {
        entropyText += " <span style='color: #ff4444;'>[ENCRYPTED]</span>";
    } else if (isPacked) {
        entropyText += " <span style='color: #ffaa00;'>[PACKED]</span>";
    } else {
        entropyText += " <span style='color: #44ff44;'>[NORMAL]</span>";
    }
    overallEntropyLabel->setText(entropyText);
    overallEntropyLabel->setTextFormat(Qt::RichText);

    statusLabel->setText(QString("%1 blocks analyzed").arg(blocks.size()));

    // Generate and display heatmap
    int heatmapWidth = qMin(800, blocks.size());
    lastHeatmap = analyzer->generateHeatmapImage(blocks, heatmapWidth, 50);
    if (!lastHeatmap.isNull()) {
        heatmapLabel->setPixmap(QPixmap::fromImage(lastHeatmap.scaled(
            heatmapScrollArea->width() - 20, 50, Qt::IgnoreAspectRatio, Qt::SmoothTransformation)));
        heatmapLabel->setStyleSheet("");
    }

    // Generate and display graph
    lastGraph = analyzer->generateEntropyGraph(blocks, heatmapScrollArea->width() - 20, 200);
    if (!lastGraph.isNull()) {
        graphLabel->setPixmap(QPixmap::fromImage(lastGraph));
        graphLabel->setStyleSheet("");
    }
}

void EntropyWindow::exportHeatmap()
{
    if (lastHeatmap.isNull()) return;

    QString fileName = QFileDialog::getSaveFileName(this, "Export Heatmap", 
        "entropy_heatmap.png", "PNG Image (*.png);;JPEG Image (*.jpg)");
    
    if (!fileName.isEmpty()) {
        if (lastHeatmap.save(fileName)) {
            QMessageBox::information(this, "Success", "Heatmap exported successfully");
        } else {
            QMessageBox::warning(this, "Error", "Failed to export heatmap");
        }
    }
}

void EntropyWindow::exportGraph()
{
    if (lastGraph.isNull()) return;

    QString fileName = QFileDialog::getSaveFileName(this, "Export Graph", 
        "entropy_graph.png", "PNG Image (*.png);;JPEG Image (*.jpg)");
    
    if (!fileName.isEmpty()) {
        if (lastGraph.save(fileName)) {
            QMessageBox::information(this, "Success", "Graph exported successfully");
        } else {
            QMessageBox::warning(this, "Error", "Failed to export graph");
        }
    }
}
