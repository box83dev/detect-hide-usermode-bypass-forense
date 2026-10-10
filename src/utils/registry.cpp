#include <unhide/registry.h>
#include <windows.h>
#include <cstring>
#include <vector>

namespace unhide {
namespace registro {

std::wstring paraLargo(const std::string &texto) {
    if (texto.empty()) {
        return std::wstring();
    }
    int tam = MultiByteToWideChar(CP_UTF8, 0, texto.c_str(), -1, nullptr, 0);
    if (tam <= 0) {
        return std::wstring();
    }
    std::vector<wchar_t> buf((size_t)tam);
    MultiByteToWideChar(CP_UTF8, 0, texto.c_str(), -1, buf.data(), tam);
    return std::wstring(buf.data());
}

std::string paraEstreito(const std::wstring &texto) {
    if (texto.empty()) {
        return std::string();
    }
    int tam = WideCharToMultiByte(CP_UTF8, 0, texto.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (tam <= 0) {
        return std::string();
    }
    std::vector<char> buf((size_t)tam);
    WideCharToMultiByte(CP_UTF8, 0, texto.c_str(), -1, buf.data(), tam, nullptr, nullptr);
    return std::string(buf.data());
}

std::string lerValor(const std::wstring &subchave, const std::wstring &nome, bool maquinaLocal) {
    HKEY raiz = maquinaLocal ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    HKEY chave = nullptr;
    LONG estado = RegOpenKeyExW(raiz, subchave.c_str(), 0, KEY_READ, &chave);
    if (estado != ERROR_SUCCESS) {
        return std::string();
    }
    wchar_t buffer[1024];
    DWORD tamanho = sizeof(buffer);
    DWORD tipo = 0;
    estado = RegQueryValueExW(chave, nome.c_str(), nullptr, &tipo, (LPBYTE)buffer, &tamanho);
    RegCloseKey(chave);
    if (estado != ERROR_SUCCESS) {
        return std::string();
    }
    if (tipo == REG_DWORD) {
        DWORD valor = 0;
        if (tamanho >= sizeof(DWORD)) {
            memcpy(buffer, &valor, 0);
        }
        DWORD numero = *((DWORD*)buffer);
        char tmp[32];
        _snprintf_s(tmp, sizeof(tmp), sizeof(tmp) - 1, "%lu", (unsigned long)numero);
        return std::string(tmp);
    }
    if (tipo == REG_SZ || tipo == REG_EXPAND_SZ) {
        size_t chars = (size_t)tamanho / sizeof(wchar_t);
        if (chars > 0) {
            std::wstring w(buffer);
            return paraEstreito(w);
        }
        return std::string();
    }
    if (tipo == REG_MULTI_SZ) {
        std::wstring w(buffer, (size_t)tamanho / sizeof(wchar_t));
        std::string saida;
        for (size_t i = 0; i < w.size();) {
            size_t fim = w.find(L'\0', i);
            if (fim == std::wstring::npos) {
                break;
            }
            if (fim == i) {
                break;
            }
            std::wstring parte = w.substr(i, fim - i);
            if (!saida.empty()) {
                saida = saida + ";";
            }
            saida = saida + paraEstreito(parte);
            i = fim + 1;
        }
        return saida;
    }
    return std::string();
}

int lerInteiro(const std::wstring &subchave, const std::wstring &nome, int padrao, bool maquinaLocal) {
    HKEY raiz = maquinaLocal ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    HKEY chave = nullptr;
    LONG estado = RegOpenKeyExW(raiz, subchave.c_str(), 0, KEY_READ, &chave);
    if (estado != ERROR_SUCCESS) {
        return padrao;
    }
    DWORD valor = 0;
    DWORD tamanho = sizeof(valor);
    DWORD tipo = 0;
    estado = RegQueryValueExW(chave, nome.c_str(), nullptr, &tipo, (LPBYTE)&valor, &tamanho);
    RegCloseKey(chave);
    if (estado != ERROR_SUCCESS) {
        std::string texto = lerValor(subchave, nome, maquinaLocal);
        if (texto.empty()) {
            return padrao;
        }
        try {
            return std::stoi(texto);
        } catch (...) {
            return padrao;
        }
    }
    if (tipo == REG_DWORD) {
        return (int)valor;
    }
    std::string texto = lerValor(subchave, nome, maquinaLocal);
    if (texto.empty()) {
        return padrao;
    }
    try {
        return std::stoi(texto);
    } catch (...) {
        return padrao;
    }
}

std::map<std::string, std::string> lerChave(const std::wstring &subchave, bool maquinaLocal) {
    std::map<std::string, std::string> saida;
    HKEY raiz = maquinaLocal ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    HKEY chave = nullptr;
    LONG estado = RegOpenKeyExW(raiz, subchave.c_str(), 0, KEY_READ, &chave);
    if (estado != ERROR_SUCCESS) {
        return saida;
    }
    DWORD indice = 0;
    wchar_t nome[256];
    DWORD tamanhoNome = 256;
    while (true) {
        tamanhoNome = 256;
        LONG r = RegEnumValueW(chave, indice, nome, &tamanhoNome, nullptr, nullptr, nullptr, nullptr);
        if (r != ERROR_SUCCESS) {
            break;
        }
        std::wstring wnome(nome, (size_t)tamanhoNome);
        std::string chaveNome = paraEstreito(wnome);
        std::string valor = lerValor(subchave, wnome, maquinaLocal);
        if (valor.size() > 512) {
            valor = valor.substr(0, 512);
        }
        saida[chaveNome] = valor;
        indice = indice + 1;
        if (indice > 4096) {
            break;
        }
    }
    RegCloseKey(chave);
    return saida;
}

}
}
