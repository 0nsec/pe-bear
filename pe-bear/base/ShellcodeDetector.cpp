#include "ShellcodeDetector.h"
#include <QFile>
#include <QTextStream>

ShellcodeDetector::ShellcodeDetector(QObject *parent)
    : QObject(parent)
{
    initializePatterns();
}

ShellcodeDetector::~ShellcodeDetector()
{
}

void ShellcodeDetector::initializePatterns()
{
    // Windows x86 shellcode patterns
    patterns.append({
        "win_x86_call_pop",
        "Windows x86 call/pop GetPC technique",
        QByteArray::fromHex("E800000000"),
        QByteArray::fromHex("FFFFFFFFFF"),
        "windows", "x86"
    });
    
    patterns.append({
        "win_x86_peb_access",
        "Windows x86 PEB access (find kernel32)",
        QByteArray::fromHex("6489250030000000"),
        QByteArray::fromHex("FFFFFFFF00FFFFFF"),
        "windows", "x86"
    });
    
    patterns.append({
        "win_x86_peb_ldr",
        "Windows x86 PEB->Ldr access",
        QByteArray::fromHex("648B4030"),
        QByteArray::fromHex("FFFFFFFF"),
        "windows", "x86"
    });
    
    patterns.append({
        "win_x86_hash_api",
        "Windows x86 API hashing technique",
        QByteArray::fromHex("60BE"),
        QByteArray::fromHex("FFFF"),
        "windows", "x86"
    });
    
    patterns.append({
        "win_x86_stackpivot",
        "Windows x86 stack pivot",
        QByteArray::fromHex("94C3"),
        QByteArray::fromHex("FFFF"),
        "windows", "x86"
    });
    
    // Windows x64 patterns
    patterns.append({
        "win_x64_peb_access",
        "Windows x64 PEB access",
        QByteArray::fromHex("6548"),
        QByteArray::fromHex("FFFF"),
        "windows", "x64"
    });
    
    patterns.append({
        "win_x64_syscall",
        "Windows x64 syscall",
        QByteArray::fromHex("0F05"),
        QByteArray::fromHex("FFFF"),
        "windows", "x64"
    });
    
    // Linux x86 patterns
    patterns.append({
        "linux_x86_int80",
        "Linux x86 int 0x80 syscall",
        QByteArray::fromHex("CD80"),
        QByteArray::fromHex("FFFF"),
        "linux", "x86"
    });
    
    patterns.append({
        "linux_x86_execve_binsh",
        "Linux x86 execve /bin/sh",
        QByteArray::fromHex("31C050682F2F7368"),
        QByteArray::fromHex("FFFFFFFFFFFFFFFF"),
        "linux", "x86"
    });
    
    // Linux x64 patterns
    patterns.append({
        "linux_x64_syscall",
        "Linux x64 syscall instruction",
        QByteArray::fromHex("0F05"),
        QByteArray::fromHex("FFFF"),
        "linux", "x64"
    });
    
    // Common patterns
    patterns.append({
        "nop_sled",
        "NOP sled (potential shellcode lead-in)",
        QByteArray::fromHex("90909090909090909090"),
        QByteArray::fromHex("FFFFFFFFFFFFFFFFFFFF"),
        "any", "x86"
    });
    
    patterns.append({
        "xor_decoder",
        "XOR decoder stub",
        QByteArray::fromHex("EB"),
        QByteArray::fromHex("FF"),
        "any", "any"
    });
    
    patterns.append({
        "egg_hunter",
        "Egg hunter shellcode pattern",
        QByteArray::fromHex("6681CAFF0F"),
        QByteArray::fromHex("FFFFFFFFFF"),
        "windows", "x86"
    });
    
    patterns.append({
        "fpu_getpc",
        "FPU-based GetPC technique",
        QByteArray::fromHex("D9EED97424F4"),
        QByteArray::fromHex("FFFFFFFFFFFF"),
        "any", "x86"
    });
}

bool ShellcodeDetector::matchPattern(const QByteArray &data, offset_t offset, const ShellcodePattern &pattern)
{
    if (offset + pattern.pattern.size() > static_cast<size_t>(data.size())) {
        return false;
    }
    
    for (int i = 0; i < pattern.pattern.size(); i++) {
        unsigned char mask = (i < pattern.mask.size()) ? 
            static_cast<unsigned char>(pattern.mask[i]) : 0xFF;
        
        if ((data[offset + i] & mask) != (pattern.pattern[i] & mask)) {
            return false;
        }
    }
    
    return true;
}

QList<ShellcodeMatch> ShellcodeDetector::scanForShellcode(const QByteArray &data)
{
    QList<ShellcodeMatch> matches;
    
    emit detectionProgress(0, "Scanning for shellcode patterns...");
    
    for (offset_t offset = 0; offset < static_cast<size_t>(data.size()); offset++) {
        if (offset % 10000 == 0) {
            int percent = static_cast<int>((static_cast<double>(offset) / data.size()) * 100);
            emit detectionProgress(percent, QString("Scanning offset 0x%1...").arg(offset, 0, 16));
        }
        
        for (const auto &pattern : patterns) {
            if (matchPattern(data, offset, pattern)) {
                // Check if we already found this at nearby offset
                bool isDuplicate = false;
                for (const auto &existing : matches) {
                    if (existing.patternName == pattern.name && 
                        qAbs(static_cast<qint64>(existing.offset) - static_cast<qint64>(offset)) < 16) {
                        isDuplicate = true;
                        break;
                    }
                }
                
                if (!isDuplicate) {
                    ShellcodeMatch match;
                    match.patternName = pattern.name;
                    match.description = pattern.description;
                    match.offset = offset;
                    match.platform = pattern.platform;
                    match.architecture = pattern.arch;
                    
                    // Try to determine shellcode size
                    match.size = findShellcodeEnd(data, offset);
                    if (match.size > 0 && match.size < 0x2000) {
                        match.data = data.mid(offset, match.size);
                    } else {
                        match.size = qMin(static_cast<size_t>(256), static_cast<size_t>(data.size()) - offset);
                        match.data = data.mid(offset, match.size);
                    }
                    
                    // Calculate confidence based on context
                    match.confidence = 0.5; // Base confidence
                    if (pattern.pattern.size() > 4) match.confidence += 0.2;
                    if (match.data.contains('\x00') && match.data.size() > 10) match.confidence -= 0.1;
                    
                    matches.append(match);
                }
            }
        }
    }
    
    emit detectionProgress(100, "Scan complete");
    emit detectionComplete(matches);
    
    return matches;
}

QList<ShellcodeMatch> ShellcodeDetector::scanSection(const QByteArray &data, const QString &sectionName, offset_t baseOffset)
{
    QList<ShellcodeMatch> matches = scanForShellcode(data);
    
    // Adjust offsets to be relative to file
    for (auto &match : matches) {
        match.offset += baseOffset;
    }
    
    return matches;
}

size_t ShellcodeDetector::findShellcodeEnd(const QByteArray &data, offset_t start)
{
    // Heuristics to find end of shellcode
    size_t maxSize = qMin(static_cast<size_t>(0x1000), static_cast<size_t>(data.size()) - start);
    
    int nullCount = 0;
    int retCount = 0;
    
    for (size_t i = 0; i < maxSize; i++) {
        unsigned char b = static_cast<unsigned char>(data[start + i]);
        
        // Count consecutive nulls
        if (b == 0x00) {
            nullCount++;
            if (nullCount > 8) {
                return i - nullCount + 1;
            }
        } else {
            nullCount = 0;
        }
        
        // Look for ret instructions
        if (b == 0xC3 || b == 0xC2) {
            retCount++;
            if (retCount > 2) {
                return i + 1;
            }
        }
    }
    
    return maxSize;
}

QByteArray ShellcodeDetector::extractShellcode(const QByteArray &data, offset_t offset, size_t maxSize)
{
    if (offset >= static_cast<size_t>(data.size())) {
        return QByteArray();
    }
    
    size_t size = findShellcodeEnd(data, offset);
    size = qMin(size, maxSize);
    size = qMin(size, static_cast<size_t>(data.size()) - offset);
    
    return data.mid(offset, size);
}

bool ShellcodeDetector::saveShellcode(const ShellcodeMatch &match, const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        emit detectionError("Cannot open file for writing: " + filePath);
        return false;
    }
    
    file.write(match.data);
    file.close();
    return true;
}

QString ShellcodeDetector::analyzeShellcode(const QByteArray &shellcode)
{
    QString analysis;
    analysis += QString("Shellcode size: %1 bytes\n\n").arg(shellcode.size());
    
    // Analyze capabilities
    QStringList caps = identifyCapabilities(shellcode);
    if (!caps.isEmpty()) {
        analysis += "Identified capabilities:\n";
        for (const QString &cap : caps) {
            analysis += "  - " + cap + "\n";
        }
        analysis += "\n";
    }
    
    // Count instruction types
    int nullCount = shellcode.count('\x00');
    int nopCount = shellcode.count('\x90');
    
    analysis += QString("Statistics:\n");
    analysis += QString("  - Null bytes: %1 (%2%)\n").arg(nullCount).arg(nullCount * 100 / shellcode.size());
    analysis += QString("  - NOP bytes: %1\n").arg(nopCount);
    
    return analysis;
}

QStringList ShellcodeDetector::identifyCapabilities(const QByteArray &shellcode)
{
    QStringList capabilities;
    
    // Check for common shellcode capabilities
    if (shellcode.contains("cmd") || shellcode.contains("command")) {
        capabilities.append("Command execution");
    }
    
    if (shellcode.contains("/bin/sh") || shellcode.contains("/bin/bash")) {
        capabilities.append("Shell spawning (Unix)");
    }
    
    if (shellcode.contains(QByteArray::fromHex("CD80"))) {
        capabilities.append("Linux syscall (int 0x80)");
    }
    
    if (shellcode.contains(QByteArray::fromHex("0F05"))) {
        capabilities.append("x64 syscall instruction");
    }
    
    if (shellcode.contains("socket") || shellcode.contains(QByteArray::fromHex("6A026A01"))) {
        capabilities.append("Network socket creation");
    }
    
    if (shellcode.contains("connect")) {
        capabilities.append("Network connection");
    }
    
    if (shellcode.contains("LoadLibrary") || shellcode.contains(QByteArray::fromHex("648B4030"))) {
        capabilities.append("Dynamic library loading");
    }
    
    if (shellcode.contains("VirtualAlloc") || shellcode.contains("mmap")) {
        capabilities.append("Memory allocation");
    }
    
    if (shellcode.contains("CreateProcess") || shellcode.contains("fork")) {
        capabilities.append("Process creation");
    }
    
    if (shellcode.contains(QByteArray::fromHex("E800000000"))) {
        capabilities.append("GetPC technique (call/pop)");
    }
    
    return capabilities;
}

QString ShellcodeDetector::toNasmSyntax(const QByteArray &shellcode)
{
    QString output;
    output += "; Shellcode - " + QString::number(shellcode.size()) + " bytes\n";
    output += "; Generated by PE-bear\n\n";
    output += "section .text\n";
    output += "global _start\n\n";
    output += "_start:\n";
    
    for (int i = 0; i < shellcode.size(); i += 16) {
        output += "    db ";
        QStringList bytes;
        for (int j = i; j < qMin(i + 16, shellcode.size()); j++) {
            bytes.append(QString("0x%1").arg(static_cast<unsigned char>(shellcode[j]), 2, 16, QChar('0')));
        }
        output += bytes.join(", ") + "\n";
    }
    
    return output;
}

QString ShellcodeDetector::toCArray(const QByteArray &shellcode)
{
    QString output;
    output += "// Shellcode - " + QString::number(shellcode.size()) + " bytes\n";
    output += "// Generated by PE-bear\n\n";
    output += "unsigned char shellcode[] = {\n";
    
    for (int i = 0; i < shellcode.size(); i += 16) {
        output += "    ";
        QStringList bytes;
        for (int j = i; j < qMin(i + 16, shellcode.size()); j++) {
            bytes.append(QString("0x%1").arg(static_cast<unsigned char>(shellcode[j]), 2, 16, QChar('0')));
        }
        output += bytes.join(", ");
        if (i + 16 < shellcode.size()) {
            output += ",";
        }
        output += "\n";
    }
    
    output += "};\n";
    output += QString("unsigned int shellcode_len = %1;\n").arg(shellcode.size());
    
    return output;
}

QString ShellcodeDetector::toPythonArray(const QByteArray &shellcode)
{
    QString output;
    output += "# Shellcode - " + QString::number(shellcode.size()) + " bytes\n";
    output += "# Generated by PE-bear\n\n";
    output += "shellcode = (\n";
    
    for (int i = 0; i < shellcode.size(); i += 16) {
        output += "    b\"";
        for (int j = i; j < qMin(i + 16, shellcode.size()); j++) {
            output += QString("\\x%1").arg(static_cast<unsigned char>(shellcode[j]), 2, 16, QChar('0'));
        }
        output += "\"\n";
    }
    
    output += ")\n";
    output += QString("# Length: %1\n").arg(shellcode.size());
    
    return output;
}
