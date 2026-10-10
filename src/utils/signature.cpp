#include <unhide/signature.h>
#include <unhide/registry.h>
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <cstring>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace unhide {
namespace assinatura {

static std::string minusculo(std::string s) {
    for (size_t i = 0; i < s.size(); i = i + 1) {
        unsigned char c = (unsigned char)s[i];
        if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') {
            s[i] = (char)(c + 32);
        }
    }
    return s;
}

static bool comecaCom(const std::string &texto, const std::string &prefixo) {
    if (prefixo.size() > texto.size()) {
        return false;
    }
    for (size_t i = 0; i < prefixo.size(); i = i + 1) {
        if (texto[i] != prefixo[i]) {
            return false;
        }
    }
    return true;
}

bool caminhoSistemaConfiavel(const std::string &caminho) {
    if (caminho.empty()) {
        return false;
    }
    char completo[MAX_PATH * 2];
    DWORD tam = GetFullPathNameA(caminho.c_str(), sizeof(completo), completo, nullptr);
    std::string normal;
    if (tam > 0 && tam < sizeof(completo)) {
        normal = std::string(completo);
    } else {
        normal = caminho;
    }
    normal = minusculo(normal);
    char winDir[MAX_PATH];
    UINT wtam = GetWindowsDirectoryA(winDir, MAX_PATH);
    std::string windows;
    if (wtam > 0) {
        windows = minusculo(std::string(winDir));
    } else {
        windows = "c:";
        windows = windows + "\\windows";
    }
    std::string s32 = windows + "\\system32";
    std::string s64 = windows + "\\syswow64";
    std::string sx = windows + "\\winsxs";
    if (comecaCom(normal, s32)) {
        return true;
    }
    if (comecaCom(normal, s64)) {
        return true;
    }
    if (comecaCom(normal, sx)) {
        return true;
    }
    return false;
}

std::string verificar(const std::string &caminho) {
    static std::map<std::string, std::string> cache;
    if (caminho.empty()) {
        return "missing";
    }
    auto hit = cache.find(caminho);
    if (hit != cache.end()) {
        return hit->second;
    }
    std::string saida = "invalid-or-missing";
    DWORD attr = GetFileAttributesA(caminho.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        saida = "file-not-found";
        cache[caminho] = saida;
        return saida;
    }
    std::wstring largo = registro::paraLargo(caminho);
    if (largo.empty()) {
        return "verify-error";
    }
    WINTRUST_FILE_INFO infoArquivo;
    memset(&infoArquivo, 0, sizeof(infoArquivo));
    infoArquivo.cbStruct = sizeof(infoArquivo);
    infoArquivo.pcwszFilePath = largo.c_str();
    infoArquivo.hFile = nullptr;
    infoArquivo.pgKnownSubject = nullptr;
    GUID acao = { 0x00AAC56B, 0xCD44, 0x11d0, { 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    WINTRUST_DATA dados;
    memset(&dados, 0, sizeof(dados));
    dados.cbStruct = sizeof(dados);
    dados.dwUIChoice = WTD_UI_NONE;
    dados.fdwRevocationChecks = WTD_REVOKE_NONE;
    dados.dwUnionChoice = WTD_CHOICE_FILE;
    dados.pFile = &infoArquivo;
    dados.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG resultado = WinVerifyTrust(nullptr, &acao, &dados);
    dados.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &acao, &dados);
    if (resultado == ERROR_SUCCESS) {
        return "valid";
    }
    return "invalid-or-missing";
}

bool ehValida(const std::string &caminho) {
    return verificar(caminho) == "valid";
}

}
}
