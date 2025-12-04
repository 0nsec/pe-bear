#pragma once

#include <QDockWidget>
#include <QLabel>
#include <QScrollArea>
#include <QPushButton>
#include <QComboBox>
#include <QSpinBox>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>

#include "../../base/EntropyAnalyzer.h"
#include "../../base/PeHandler.h"

class EntropyWindow : public QDockWidget
{
    Q_OBJECT

public:
    explicit EntropyWindow(QWidget *parent = nullptr);
    ~EntropyWindow();

    void setPeHandler(PeHandler *handler);

public slots:
    void analyzeEntropy();
    void onAnalysisComplete(const QList<EntropyBlock> &blocks);
    void exportHeatmap();
    void exportGraph();

private:
    void setupUI();
    void updateDisplay(const QList<EntropyBlock> &blocks);

    PeHandler *peHandler;
    EntropyAnalyzer *analyzer;

    // UI Elements
    QWidget *mainWidget;
    QLabel *heatmapLabel;
    QLabel *graphLabel;
    QLabel *overallEntropyLabel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    
    QSpinBox *blockSizeSpinBox;
    QComboBox *visualizationCombo;
    QPushButton *analyzeButton;
    QPushButton *exportHeatmapButton;
    QPushButton *exportGraphButton;
    
    QScrollArea *heatmapScrollArea;
    QScrollArea *graphScrollArea;
    
    // Section entropy table
    QWidget *sectionTable;
    
    // Cached results
    QList<EntropyBlock> lastResults;
    QImage lastHeatmap;
    QImage lastGraph;
};
