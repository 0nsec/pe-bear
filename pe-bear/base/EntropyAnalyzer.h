#pragma once

#include <QtCore>
#include <QObject>
#include <QImage>
#include <QColor>

typedef uint64_t offset_t;

struct EntropyBlock {
    offset_t offset;
    size_t size;
    double entropy;
    QString sectionName;
    bool isPacked;
    bool isEncrypted;
};

class EntropyAnalyzer : public QObject
{
    Q_OBJECT

signals:
    void analysisComplete(const QList<EntropyBlock> &blocks);
    void analysisError(const QString &error);

public:
    explicit EntropyAnalyzer(QObject *parent = nullptr);
    ~EntropyAnalyzer();

    // Calculate entropy
    static double calculateEntropy(const QByteArray &data);
    static double calculateEntropy(const unsigned char *data, size_t size);
    
    // Analyze file
    QList<EntropyBlock> analyzeFile(const QByteArray &fileData, size_t blockSize = 256);
    QList<EntropyBlock> analyzeBySection(const QByteArray &fileData, const QList<QPair<QString, QPair<offset_t, size_t>>> &sections);
    
    // Visualization
    QImage generateEntropyMap(const QList<EntropyBlock> &blocks, int width = 800, int height = 100);
    QImage generateEntropyGraph(const QList<EntropyBlock> &blocks, int width = 800, int height = 200);
    
    // Detection
    static bool isLikelyPacked(double entropy);
    static bool isLikelyEncrypted(double entropy);
    static QString getEntropyAssessment(double entropy);
    
    // Color mapping
    static QColor entropyToColor(double entropy);

private:
    static const double PACKED_THRESHOLD;
    static const double ENCRYPTED_THRESHOLD;
};
