#pragma once

#include <QDockWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QProgressBar>
#include <QLabel>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QGroupBox>

#include "../../base/ReportGenerator.h"
#include "../../base/PeHandler.h"

class ReportWindow : public QDockWidget
{
    Q_OBJECT

public:
    explicit ReportWindow(QWidget *parent = nullptr);
    ~ReportWindow();

    void setPeHandler(PeHandler *handler);
    void setAnalysisResults(const AnalysisReport &report);

public slots:
    void generateReport();
    void previewReport();
    void onReportGenerated(const QString &path);

private:
    void setupUI();
    AnalysisReport gatherReportData();

    PeHandler *peHandler;
    ReportGenerator *generator;

    // UI Elements
    QWidget *mainWidget;
    QComboBox *formatCombo;
    QLineEdit *titleEdit;
    QLineEdit *analystEdit;
    QTextEdit *previewText;
    QProgressBar *progressBar;
    QLabel *statusLabel;
    
    // Include checkboxes
    QCheckBox *includeFileInfo;
    QCheckBox *includeSecurity;
    QCheckBox *includeEntropy;
    QCheckBox *includePackers;
    QCheckBox *includeIOCs;
    QCheckBox *includeShellcode;
    QCheckBox *includeYara;
    QCheckBox *includeAI;
    
    QPushButton *previewButton;
    QPushButton *generateButton;

    // Cached report data
    AnalysisReport currentReport;
    bool hasExternalData;
};
