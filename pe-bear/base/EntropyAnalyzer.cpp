#include "EntropyAnalyzer.h"
#include <QPainter>
#include <QPainterPath>
#include <cmath>

const double EntropyAnalyzer::PACKED_THRESHOLD = 6.5;
const double EntropyAnalyzer::ENCRYPTED_THRESHOLD = 7.5;

EntropyAnalyzer::EntropyAnalyzer(QObject *parent)
    : QObject(parent)
{
}

EntropyAnalyzer::~EntropyAnalyzer()
{
}

double EntropyAnalyzer::calculateEntropy(const QByteArray &data)
{
    return calculateEntropy(reinterpret_cast<const unsigned char*>(data.constData()), data.size());
}

double EntropyAnalyzer::calculateEntropy(const unsigned char *data, size_t size)
{
    if (size == 0) return 0.0;
    
    // Count byte frequencies
    size_t frequency[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }
    
    // Calculate entropy using Shannon's formula
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = static_cast<double>(frequency[i]) / size;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

QList<EntropyBlock> EntropyAnalyzer::analyzeFile(const QByteArray &fileData, size_t blockSize)
{
    QList<EntropyBlock> blocks;
    
    if (fileData.isEmpty()) {
        emit analysisError("Empty file data");
        return blocks;
    }
    
    size_t totalSize = fileData.size();
    size_t offset = 0;
    
    while (offset < totalSize) {
        size_t currentBlockSize = qMin(blockSize, totalSize - offset);
        
        EntropyBlock block;
        block.offset = offset;
        block.size = currentBlockSize;
        block.entropy = calculateEntropy(
            reinterpret_cast<const unsigned char*>(fileData.constData() + offset),
            currentBlockSize
        );
        block.isPacked = isLikelyPacked(block.entropy);
        block.isEncrypted = isLikelyEncrypted(block.entropy);
        
        blocks.append(block);
        offset += blockSize;
    }
    
    emit analysisComplete(blocks);
    return blocks;
}

QList<EntropyBlock> EntropyAnalyzer::analyzeBySection(const QByteArray &fileData, 
    const QList<QPair<QString, QPair<offset_t, size_t>>> &sections)
{
    QList<EntropyBlock> blocks;
    
    for (const auto &section : sections) {
        QString name = section.first;
        offset_t offset = section.second.first;
        size_t size = section.second.second;
        
        if (offset + size > static_cast<size_t>(fileData.size())) {
            continue;
        }
        
        EntropyBlock block;
        block.offset = offset;
        block.size = size;
        block.sectionName = name;
        block.entropy = calculateEntropy(
            reinterpret_cast<const unsigned char*>(fileData.constData() + offset),
            size
        );
        block.isPacked = isLikelyPacked(block.entropy);
        block.isEncrypted = isLikelyEncrypted(block.entropy);
        
        blocks.append(block);
    }
    
    emit analysisComplete(blocks);
    return blocks;
}

QImage EntropyAnalyzer::generateEntropyMap(const QList<EntropyBlock> &blocks, int width, int height)
{
    QImage image(width, height, QImage::Format_RGB32);
    image.fill(Qt::black);
    
    if (blocks.isEmpty()) return image;
    
    QPainter painter(&image);
    
    // Calculate total size
    offset_t totalSize = 0;
    for (const auto &block : blocks) {
        totalSize = qMax(totalSize, block.offset + block.size);
    }
    
    if (totalSize == 0) return image;
    
    // Draw each block
    for (const auto &block : blocks) {
        int x = static_cast<int>((static_cast<double>(block.offset) / totalSize) * width);
        int blockWidth = qMax(1, static_cast<int>((static_cast<double>(block.size) / totalSize) * width));
        
        QColor color = entropyToColor(block.entropy);
        painter.fillRect(x, 0, blockWidth, height, color);
    }
    
    // Draw scale
    painter.setPen(Qt::white);
    painter.drawText(5, height - 5, "0");
    painter.drawText(width - 40, height - 5, QString::number(totalSize, 16));
    
    return image;
}

QImage EntropyAnalyzer::generateEntropyGraph(const QList<EntropyBlock> &blocks, int width, int height)
{
    QImage image(width, height, QImage::Format_RGB32);
    image.fill(QColor(30, 30, 30));
    
    if (blocks.isEmpty()) return image;
    
    QPainter painter(&image);
    painter.setRenderHint(QPainter::Antialiasing);
    
    // Draw grid
    painter.setPen(QColor(60, 60, 60));
    for (int i = 0; i <= 8; i++) {
        int y = height - (i * height / 8);
        painter.drawLine(0, y, width, y);
        painter.setPen(Qt::gray);
        painter.drawText(5, y - 2, QString::number(i));
        painter.setPen(QColor(60, 60, 60));
    }
    
    // Draw threshold lines
    painter.setPen(QPen(QColor(255, 165, 0), 1, Qt::DashLine));
    int packedY = height - static_cast<int>((PACKED_THRESHOLD / 8.0) * height);
    painter.drawLine(0, packedY, width, packedY);
    
    painter.setPen(QPen(QColor(255, 0, 0), 1, Qt::DashLine));
    int encryptedY = height - static_cast<int>((ENCRYPTED_THRESHOLD / 8.0) * height);
    painter.drawLine(0, encryptedY, width, encryptedY);
    
    // Draw entropy curve
    QPainterPath path;
    bool first = true;
    
    for (int i = 0; i < blocks.size(); i++) {
        double x = (static_cast<double>(i) / blocks.size()) * width;
        double y = height - (blocks[i].entropy / 8.0) * height;
        
        if (first) {
            path.moveTo(x, y);
            first = false;
        } else {
            path.lineTo(x, y);
        }
    }
    
    // Fill under curve with gradient
    QPainterPath fillPath = path;
    fillPath.lineTo(width, height);
    fillPath.lineTo(0, height);
    fillPath.closeSubpath();
    
    QLinearGradient gradient(0, 0, 0, height);
    gradient.setColorAt(0.0, QColor(255, 0, 0, 100));
    gradient.setColorAt(0.5, QColor(255, 165, 0, 80));
    gradient.setColorAt(1.0, QColor(0, 255, 0, 60));
    painter.fillPath(fillPath, gradient);
    
    // Draw curve line
    painter.setPen(QPen(Qt::white, 2));
    painter.drawPath(path);
    
    // Legend
    painter.setPen(Qt::white);
    painter.drawText(width - 150, 20, "Packed threshold (6.5)");
    painter.drawText(width - 150, 35, "Encrypted threshold (7.5)");
    
    return image;
}

bool EntropyAnalyzer::isLikelyPacked(double entropy)
{
    return entropy >= PACKED_THRESHOLD;
}

bool EntropyAnalyzer::isLikelyEncrypted(double entropy)
{
    return entropy >= ENCRYPTED_THRESHOLD;
}

QString EntropyAnalyzer::getEntropyAssessment(double entropy)
{
    if (entropy < 1.0) {
        return "Very low - Mostly null/uniform data";
    } else if (entropy < 3.0) {
        return "Low - Plain text or simple data";
    } else if (entropy < 5.0) {
        return "Medium - Normal code/data";
    } else if (entropy < 6.5) {
        return "Elevated - Possibly compressed";
    } else if (entropy < 7.5) {
        return "High - Likely packed/compressed";
    } else {
        return "Very high - Likely encrypted";
    }
}

QColor EntropyAnalyzer::entropyToColor(double entropy)
{
    // Map entropy (0-8) to color gradient
    // Low (0-3): Green
    // Medium (3-6): Yellow
    // High (6-8): Red
    
    if (entropy < 3.0) {
        int g = 255;
        int r = static_cast<int>((entropy / 3.0) * 255);
        return QColor(r, g, 0);
    } else if (entropy < 6.0) {
        int r = 255;
        int g = 255 - static_cast<int>(((entropy - 3.0) / 3.0) * 255);
        return QColor(r, g, 0);
    } else {
        int r = 255;
        int g = 0;
        int b = static_cast<int>(((entropy - 6.0) / 2.0) * 128);
        return QColor(r, g, b);
    }
}
