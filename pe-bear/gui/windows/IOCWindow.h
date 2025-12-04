#pragma once

#include <QDockWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QCheckBox>
#include <QLabel>

#include "../../base/IOCExtractor.h"
#include "../../base/PeHandler.h"

class IOCWindow : public QDockWidget
{
    Q_OBJECT

public:
    explicit IOCWindow(QWidget *parent = nullptr);
    ~IOCWindow();

    void setPeHandler(PeHandler *handler);

public slots:
    void extractIOCs();
    void onExtractionComplete(const QList<IOC> &iocs);
    void exportResults();
    void filterResults(const QString &text);
    void copySelected();

private:
    void setupUI();
    void populateTable(const QList<IOC> &iocs);

    PeHandler *peHandler;
    IOCExtractor *extractor;

    // UI Elements
    QWidget *mainWidget;
    QTableWidget *iocTable;
    QLineEdit *filterEdit;
    QComboBox *typeFilterCombo;
    QComboBox *exportFormatCombo;
    QProgressBar *progressBar;
    QLabel *statusLabel;
    
    QPushButton *extractButton;
    QPushButton *exportButton;
    QPushButton *copyButton;
    
    // Filter checkboxes
    QCheckBox *showURLs;
    QCheckBox *showIPs;
    QCheckBox *showDomains;
    QCheckBox *showEmails;
    QCheckBox *showPaths;
    QCheckBox *showHashes;
    QCheckBox *suspiciousOnly;

    // Cached results
    QList<IOC> allIOCs;
};
