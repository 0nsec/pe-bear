#include "UnpackerDetector.h"
#include <QProcess>
#include <QFile>
#include <QFileInfo>
#include <QDir>

UnpackerDetector::UnpackerDetector(QObject *parent)
    : QObject(parent)
{
    initSignatures();
}

UnpackerDetector::~UnpackerDetector()
{
}

void UnpackerDetector::initSignatures()
{
    // UPX signatures
    signatures.append({
        "UPX", "3.x+",
        QByteArray::fromHex("60BE????????8DBE????????5783CDFF"),
        QByteArray::fromHex("FFFFxxxxxxxxxxxxFFFFFFFF"),
        0
    });
    
    signatures.append({
        "UPX", "2.x",
        QByteArray::fromHex("60E8000000005883C008"),
        QByteArray(),
        0
    });
    
    signatures.append({
        "UPX", "0.8x",
        QByteArray::fromHex("8060BE????????"),
        QByteArray::fromHex("FFFFFFFF"),
        0
    });
    
    // ASPack signatures
    signatures.append({
        "ASPack", "2.12+",
        QByteArray::fromHex("60E803000000E9EB045D4555C3E801"),
        QByteArray(),
        0
    });
    
    signatures.append({
        "ASPack", "2.1",
        QByteArray::fromHex("60E872050000EB33"),
        QByteArray(),
        0
    });
    
    // PECompact signatures
    signatures.append({
        "PECompact", "2.x",
        QByteArray::fromHex("B800????????01E8????????????????????78"),
        QByteArray::fromHex("FFxxxxFFFFxxxxxxxxxxxxxxxxxxFFFFFF"),
        0
    });
    
    // Themida / WinLicense signatures
    signatures.append({
        "Themida", "1.x-2.x",
        QByteArray::fromHex("B80000????600BC07458E8????????0000"),
        QByteArray::fromHex("FFFFFFxxxxFFFFFFFFFFxxxxxxFFFF"),
        0
    });
    
    signatures.append({
        "WinLicense", "2.x",
        QByteArray::fromHex("EB02????6085F074"),
        QByteArray::fromHex("FFFFFFFFFFFF"),
        0
    });
    
    // VMProtect signatures
    signatures.append({
        "VMProtect", "1.x-2.x",
        QByteArray::fromHex("68????????E8????????"),
        QByteArray::fromHex("FFxxxxxxxxFFxxxxxxxx"),
        0
    });
    
    signatures.append({
        "VMProtect", "3.x",
        QByteArray::fromHex("90909090909090909090909090909090E8"),
        QByteArray(),
        -1
    });
    
    // FSG signatures
    signatures.append({
        "FSG", "1.3x",
        QByteArray::fromHex("BBD0014000BF00104000BE????????"),
        QByteArray::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFxxxxxxxx"),
        0
    });
    
    signatures.append({
        "FSG", "2.0",
        QByteArray::fromHex("87254000BBF4534000EB0208AD"),
        QByteArray::fromHex("FFxxFFFFFFxxxxxxFFFFFFFFFF"),
        0
    });
    
    // MEW signatures
    signatures.append({
        "MEW", "11 SE 1.x",
        QByteArray::fromHex("E9????????0000000002000000"),
        QByteArray::fromHex("FFxxxxxxxxFFFFFFFFFFFFFFFF"),
        0
    });
    
    // MPRESS signatures
    signatures.append({
        "MPRESS", "1.x-2.x",
        QByteArray::fromHex("60E8????????5D"),
        QByteArray(),
        0
    });
    
    // NsPack signatures
    signatures.append({
        "NsPack", "2.x-3.x",
        QByteArray::fromHex("9C60E8000000005DB800????"),
        QByteArray::fromHex("FFFFFFFFFFFFFFFFFFFFxxxxxx"),
        0
    });
    
    // Obsidium signatures
    signatures.append({
        "Obsidium", "1.x",
        QByteArray::fromHex("EB02????????E8????FF"),
        QByteArray(),
        0
    });
    
    // PELock signatures
    signatures.append({
        "PELock", "1.x",
        QByteArray::fromHex("EB0315EB02CD20EB021ECD"),
        QByteArray(),
        0
    });
    
    // Petite signatures
    signatures.append({
        "Petite", "2.x",
        QByteArray::fromHex("B800????008D????????68????????64FF35"),
        QByteArray::fromHex("FFFFxxxxFFFFxxxxxxxxFFxxxxxxxxFFFFFF"),
        0
    });
    
    // RLPack signatures
    signatures.append({
        "RLPack", "1.x",
        QByteArray::fromHex("60E8000000008B2C2483C404"),
        QByteArray(),
        0
    });
    
    // EZIP signatures
    signatures.append({
        "EZIP", "1.0",
        QByteArray::fromHex("E9B5000000????00"),
        QByteArray::fromHex("FFFFFFFFFFFF????FF"),
        0
    });
    
    // ExeStealth signatures
    signatures.append({
        "ExeStealth", "2.x",
        QByteArray::fromHex("EB0060EB????E8????????"),
        QByteArray::fromHex("FFFFFFFF????FFxxxxxxxx"),
        0
    });
}

QList<PackerInfo> UnpackerDetector::detectPackers(const QByteArray &fileData, const QStringList &sectionNames)
{
    QList<PackerInfo> results;
    
    emit progressUpdate(0, "Starting packer detection...");
    
    // Check by signatures
    QByteArray entryData = fileData.left(256); // First 256 bytes
    PackerInfo sigResult = detectBySignature(entryData);
    if (!sigResult.name.isEmpty()) {
        results.append(sigResult);
    }
    
    emit progressUpdate(30, "Checking section names...");
    
    // Check section names for known packer indicators
    for (const QString &section : sectionNames) {
        PackerInfo sectionResult = detectBySection(section);
        if (!sectionResult.name.isEmpty()) {
            // Check if already detected
            bool found = false;
            for (const PackerInfo &existing : results) {
                if (existing.name == sectionResult.name) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                results.append(sectionResult);
            }
        }
    }
    
    emit progressUpdate(60, "Analyzing entropy...");
    
    // Calculate and check entropy
    if (fileData.size() > 0) {
        double entropy = 0.0;
        int counts[256] = {0};
        
        for (char c : fileData) {
            counts[static_cast<unsigned char>(c)]++;
        }
        
        for (int i = 0; i < 256; i++) {
            if (counts[i] > 0) {
                double p = static_cast<double>(counts[i]) / fileData.size();
                entropy -= p * log2(p);
            }
        }
        
        PackerInfo entropyResult = detectByEntropy(entropy);
        if (!entropyResult.name.isEmpty() && results.isEmpty()) {
            results.append(entropyResult);
        }
    }
    
    emit progressUpdate(100, "Detection complete");
    emit detectionComplete(results);
    
    return results;
}

PackerInfo UnpackerDetector::detectBySection(const QString &sectionName)
{
    PackerInfo result;
    QString upper = sectionName.toUpper().trimmed();
    
    // Known packer section names
    if (upper == "UPX0" || upper == "UPX1" || upper == "UPX2" || upper == ".UPX") {
        result.name = "UPX";
        result.description = "Ultimate Packer for eXecutables";
        result.confidence = 0.95;
        result.canUnpack = true;
        result.unpackCommand = "upx -d";
    }
    else if (upper == ".ASPACK" || upper == ".ADATA") {
        result.name = "ASPack";
        result.description = "ASPack software packer";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".THEMIDA") {
        result.name = "Themida";
        result.description = "Advanced software protector by Oreans";
        result.confidence = 0.95;
        result.canUnpack = false;
    }
    else if (upper == ".VMPX" || upper == ".VMPn") {
        result.name = "VMProtect";
        result.description = "Virtual machine based software protector";
        result.confidence = 0.95;
        result.canUnpack = false;
    }
    else if (upper == "PEBUNDLE" || upper == ".PEBUNDLE") {
        result.name = "PEBundle";
        result.description = "PEBundle file joiner/packer";
        result.confidence = 0.85;
        result.canUnpack = false;
    }
    else if (upper == "PECOMPACT" || upper == ".PECOMPACT" || upper == "PEC2") {
        result.name = "PECompact";
        result.description = "PECompact executable compressor";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".PKLITE" || upper == "PKLITE32") {
        result.name = "PKLite32";
        result.description = "PKLite executable compressor";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".ENIGMA1" || upper == ".ENIGMA2") {
        result.name = "Enigma";
        result.description = "Enigma Protector";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".MPRESS" || upper == ".MPRESS1" || upper == ".MPRESS2") {
        result.name = "MPRESS";
        result.description = "MPRESS executable packer";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".NSPACK" || upper == "NSPXX") {
        result.name = "NsPack";
        result.description = "NsPack executable packer";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".PETITE") {
        result.name = "Petite";
        result.description = "Petite executable compressor";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".RLPACK") {
        result.name = "RLPack";
        result.description = "RLPack executable packer";
        result.confidence = 0.90;
        result.canUnpack = false;
    }
    else if (upper == ".YODA") {
        result.name = "YodaCrypt";
        result.description = "Yoda's Crypter";
        result.confidence = 0.85;
        result.canUnpack = false;
    }
    else if (upper == ".PERPLEX") {
        result.name = "Perplex";
        result.description = "PE Perplex executable protector";
        result.confidence = 0.85;
        result.canUnpack = false;
    }
    else if (upper == ".ARMADILLO" || upper == ".ARM") {
        result.name = "Armadillo";
        result.description = "Armadillo software protection";
        result.confidence = 0.85;
        result.canUnpack = false;
    }
    else if (upper == ".WINUNIX" || upper == ".WWPACK") {
        result.name = "WWPack32";
        result.description = "WWPack32 executable packer";
        result.confidence = 0.85;
        result.canUnpack = false;
    }
    
    return result;
}

PackerInfo UnpackerDetector::detectByEntropy(double entropy)
{
    PackerInfo result;
    
    if (entropy > 7.5) {
        result.name = "Unknown (Encrypted/Packed)";
        result.description = "High entropy indicates encrypted or packed content";
        result.confidence = 0.70;
        result.canUnpack = false;
    }
    else if (entropy > 6.8) {
        result.name = "Unknown (Likely Packed)";
        result.description = "Elevated entropy suggests compressed content";
        result.confidence = 0.50;
        result.canUnpack = false;
    }
    
    return result;
}

PackerInfo UnpackerDetector::detectBySignature(const QByteArray &entryPointData)
{
    PackerInfo result;
    
    for (const PackerSignature &sig : signatures) {
        if (sig.offset >= 0 && entryPointData.size() < sig.offset + sig.signature.size()) {
            continue;
        }
        
        int startOffset = (sig.offset < 0) ? 0 : sig.offset;
        int endOffset = (sig.offset < 0) ? entryPointData.size() - sig.signature.size() : sig.offset;
        
        for (int offset = startOffset; offset <= endOffset; offset++) {
            bool matches = true;
            
            for (int i = 0; i < sig.signature.size() && offset + i < entryPointData.size(); i++) {
                // Check if we have a mask and if this byte should be ignored
                if (!sig.mask.isEmpty() && i < sig.mask.size()) {
                    if (sig.mask[i] != '\xFF') {
                        continue; // Skip masked byte
                    }
                }
                
                if (entryPointData[offset + i] != sig.signature[i]) {
                    matches = false;
                    break;
                }
            }
            
            if (matches) {
                result.name = sig.packerName;
                result.version = sig.version;
                result.description = getPackerDescription(sig.packerName);
                result.confidence = 0.90;
                result.signatures.append(sig.signature.toHex());
                
                // Set unpack capability
                if (sig.packerName == "UPX") {
                    result.canUnpack = true;
                    result.unpackCommand = "upx -d";
                } else {
                    result.canUnpack = false;
                }
                
                return result;
            }
        }
    }
    
    return result;
}

bool UnpackerDetector::unpackUPX(const QString &inputPath, const QString &outputPath)
{
    QString output;
    
    // First check if UPX is available
    if (!runExternalTool("upx", {"--version"}, output)) {
        emit unpackError("UPX tool not found. Please install UPX to unpack this file.");
        return false;
    }
    
    emit progressUpdate(10, "UPX detected, starting unpack...");
    
    // Copy input to output path first
    if (inputPath != outputPath) {
        QFile::copy(inputPath, outputPath);
    }
    
    emit progressUpdate(30, "Running UPX decompression...");
    
    // Run UPX to decompress
    QStringList args = {"-d", "-o", outputPath + ".tmp", inputPath};
    
    if (!runExternalTool("upx", args, output)) {
        // Try with overwrite flag
        args = {"-d", "-f", "-o", outputPath, inputPath};
        if (!runExternalTool("upx", args, output)) {
            emit unpackError("UPX unpacking failed: " + output);
            return false;
        }
    } else {
        // Rename temp file
        QFile::remove(outputPath);
        QFile::rename(outputPath + ".tmp", outputPath);
    }
    
    emit progressUpdate(100, "Unpack complete!");
    emit unpackComplete(outputPath);
    return true;
}

bool UnpackerDetector::unpackASPack(const QString &inputPath, const QString &outputPath)
{
    emit unpackError("ASPack unpacking requires external tools that are not currently supported.");
    return false;
}

bool UnpackerDetector::unpackGeneric(const QString &inputPath, const QString &outputPath)
{
    emit unpackError("Generic unpacking is not implemented. Consider using specialized tools.");
    return false;
}

QStringList UnpackerDetector::getSupportedPackers()
{
    return QStringList{
        "UPX",
        "ASPack",
        "PECompact",
        "Themida",
        "WinLicense",
        "VMProtect",
        "FSG",
        "MEW",
        "MPRESS",
        "NsPack",
        "Obsidium",
        "PELock",
        "Petite",
        "RLPack",
        "EZIP",
        "ExeStealth",
        "Enigma",
        "Armadillo",
        "PKLite32",
        "WWPack32",
        "YodaCrypt"
    };
}

bool UnpackerDetector::isUnpackerAvailable(const QString &packerName)
{
    if (packerName.toUpper() == "UPX") {
        QString output;
        return runExternalTool("upx", {"--version"}, output);
    }
    // Most packers don't have free command-line unpackers
    return false;
}

QString UnpackerDetector::getPackerDescription(const QString &packerName)
{
    static QHash<QString, QString> descriptions = {
        {"UPX", "Ultimate Packer for eXecutables - Free, portable, and extendable packer"},
        {"ASPack", "Advanced commercial software packer"},
        {"PECompact", "Windows executable compressor"},
        {"Themida", "Advanced software protection system by Oreans Technologies"},
        {"WinLicense", "Advanced software protection and licensing by Oreans Technologies"},
        {"VMProtect", "Advanced software protection using virtualization"},
        {"FSG", "Fast Small Good - Simple executable packer"},
        {"MEW", "Small and fast executable packer"},
        {"MPRESS", "Free portable executable packer"},
        {"NsPack", "Executable packer for PE files"},
        {"Obsidium", "Commercial software protection system"},
        {"PELock", "Software protection system"},
        {"Petite", "Executable file compressor for Windows"},
        {"RLPack", "Basic executable packer"},
        {"EZIP", "Simple executable zipper"},
        {"ExeStealth", "Software protection and anti-debugging tool"},
        {"Enigma", "Enigma Protector - Software protection system"},
        {"Armadillo", "Software protection with hardware fingerprinting"},
        {"PKLite32", "Executable file compressor"},
        {"WWPack32", "32-bit executable packer"},
        {"YodaCrypt", "Crypter and packer tool"}
    };
    
    return descriptions.value(packerName, "Unknown packer");
}

bool UnpackerDetector::runExternalTool(const QString &command, const QStringList &args, QString &output)
{
    QProcess process;
    process.start(command, args);
    
    if (!process.waitForStarted(5000)) {
        output = "Failed to start: " + process.errorString();
        return false;
    }
    
    if (!process.waitForFinished(60000)) {
        output = "Process timed out";
        process.kill();
        return false;
    }
    
    output = QString::fromUtf8(process.readAllStandardOutput());
    QString errorOutput = QString::fromUtf8(process.readAllStandardError());
    
    if (!errorOutput.isEmpty()) {
        output += "\n" + errorOutput;
    }
    
    return process.exitCode() == 0;
}
