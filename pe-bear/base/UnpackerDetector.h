#pragma once

#include <QtCore>
#include <QObject>

struct PackerInfo {
    QString name;
    QString version;
    QString description;
    double confidence;
    QStringList signatures;
    bool canUnpack;
    QString unpackCommand;
};

class UnpackerDetector : public QObject
{
    Q_OBJECT

signals:
    void detectionComplete(const QList<PackerInfo> &packers);
    void unpackComplete(const QString &outputPath);
    void unpackError(const QString &error);
    void progressUpdate(int percent, const QString &status);

public:
    explicit UnpackerDetector(QObject *parent = nullptr);
    ~UnpackerDetector();

    // Detection
    QList<PackerInfo> detectPackers(const QByteArray &fileData, const QStringList &sectionNames);
    PackerInfo detectBySection(const QString &sectionName);
    PackerInfo detectByEntropy(double entropy);
    PackerInfo detectBySignature(const QByteArray &entryPointData);
    
    // Unpacking
    bool unpackUPX(const QString &inputPath, const QString &outputPath);
    bool unpackASPack(const QString &inputPath, const QString &outputPath);
    bool unpackGeneric(const QString &inputPath, const QString &outputPath);
    
    // Get supported unpackers
    QStringList getSupportedPackers();
    bool isUnpackerAvailable(const QString &packerName);
    
    // Helper
    static QString getPackerDescription(const QString &packerName);

private:
    struct PackerSignature {
        QString packerName;
        QString version;
        QByteArray signature;
        QByteArray mask;
        int offset; // -1 for any, 0 for entry point, etc.
    };
    
    QList<PackerSignature> signatures;
    void initSignatures();
    
    bool runExternalTool(const QString &command, const QStringList &args, QString &output);
};
