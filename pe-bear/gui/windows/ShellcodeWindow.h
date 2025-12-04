#pragma once

#include <QDockWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QGroupBox>

#include "../../base/ShellcodeDetector.h"
#include "../../base/PeHandler.h"

class ShellcodeWindow : public QDockWidget
{
    Q_OBJECT

public:
    explicit ShellcodeWindow(QWidget *parent = nullptr);
    ~ShellcodeWindow();

    void setPeHandler(PeHandler *handler);

public slots:
    void scanForShellcode();
    void onDetectionComplete(const QList<ShellcodeMatch> &matches);
    void showDetails(int row, int column);
    void exportShellcode();

private:
    void setupUI();
    void populateTable(const QList<ShellcodeMatch> &matches);

    PeHandler *peHandler;
    ShellcodeDetector *detector;

    // UI Elements
    QWidget *mainWidget;
    QTableWidget *resultsTable;
    QTextEdit *detailsView;
    QTextEdit *hexView;
    QProgressBar *progressBar;
    QLabel *statusLabel;
    
    QPushButton *scanButton;
    QPushButton *exportButton;

    // Cached results
    QList<ShellcodeMatch> allMatches;
};
