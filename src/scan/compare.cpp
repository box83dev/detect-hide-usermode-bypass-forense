#include <unhide/compare.h>
#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <vector>
#include <set>
#include <algorithm>

namespace unhide {
namespace comparacao {

typedef NTSTATUS(NTAPI *TipoNtQuery)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

typedef NTSTATUS(NTAPI *TipoNtOpen)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

struct BlocoDiretorio {
    ULONG proximo;
    ULONG indice;
    LARGE_INTEGER criacao;
    LARGE_INTEGER acesso;
    LARGE_INTEGER escrita;
    LARGE_INTEGER alteracao;
    LARGE_INTEGER fimArquivo;
    LARGE_INTEGER alocacao;
    ULONG atributos;
    ULONG tamanhoNome;
    WCHAR nome[1];
};

static std::wstring largo(const std::string &s) {
    if (s.empty()) {
        return std::wstring();
    }
    int tam = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (tam <= 0) {
        return std::wstring();
    }
    std::wstring w((size_t)tam - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), tam);
    return w;
}

static std::string estreito(const std::wstring &w) {
    if (w.empty()) {
        return std::string();
    }
    int tam = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (tam <= 0) {
        return std::string();
    }
    std::string s((size_t)tam - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), tam, nullptr, nullptr);
    return s;
}

static std::string menorTexto(std::string s) {
    for (size_t i = 0; i < s.size(); i = i + 1) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            s[i] = (char)(c + 32);
        }
    }
    return s;
}

static std::set<std::string> listarWin32(const std::string &diretorio) {
    std::set<std::string> nomes;
    std::wstring wdir = largo(diretorio);
    std::wstring padrao = wdir;
    if (!padrao.empty() && padrao[padrao.size() - 1] != L'\\') {
        padrao = padrao + L"\\";
    }
    padrao = padrao + L"*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(padrao.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return nomes;
    }
    do {
        std::wstring wn = fd.cFileName;
        if (wn == L"." || wn == L"..") {
            continue;
        }
        std::string n = menorTexto(estreito(wn));
        nomes.insert(n);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return nomes;
}

static std::set<std::string> listarNativo(const std::string &diretorio) {
    std::set<std::string> nomes;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return nomes;
    }
    TipoNtQuery fn = (TipoNtQuery)GetProcAddress(ntdll, "NtQueryDirectoryFile");
    if (fn == nullptr) {
        return nomes;
    }
    TipoNtOpen abre = (TipoNtOpen)GetProcAddress(ntdll, "NtOpenFile");
    if (abre == nullptr) {
        return nomes;
    }
    std::wstring wdir = largo(diretorio);
    std::wstring caminhoNt = L"\\??\\" + wdir;
    UNICODE_STRING unome;
    unome.Buffer = caminhoNt.data();
    unome.Length = (USHORT)(caminhoNt.size() * sizeof(wchar_t));
    unome.MaximumLength = (USHORT)((caminhoNt.size() + 1) * sizeof(wchar_t));
    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &unome, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE h = nullptr;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = abre(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (st != 0 || h == nullptr) {
        return nomes;
    }
    const ULONG tamBuf = 65536;
    std::vector<unsigned char> buf(tamBuf);
    bool primeiro = true;
    while (true) {
        IO_STATUS_BLOCK iosb2;
        NTSTATUS r = fn(h, nullptr, nullptr, nullptr, &iosb2, buf.data(), tamBuf, FileDirectoryInformation, FALSE, nullptr, primeiro ? TRUE : FALSE);
        primeiro = false;
        if (r != 0) {
            break;
        }
        ULONG desloc = 0;
        while (true) {
            BlocoDiretorio *info = (BlocoDiretorio*)(buf.data() + desloc);
            std::wstring wn(info->nome, info->tamanhoNome / sizeof(wchar_t));
            if (wn != L"." && wn != L"..") {
                std::string n = menorTexto(estreito(wn));
                nomes.insert(n);
            }
            if (info->proximo == 0) {
                break;
            }
            desloc = desloc + info->proximo;
            if (desloc >= tamBuf) {
                break;
            }
        }
    }
    CloseHandle(h);
    return nomes;
}

modelos::DivergenciaVisao compararDiretorio(const std::string &diretorio) {
    modelos::DivergenciaVisao d;
    d.diretorio = diretorio;
    std::set<std::string> alto;
    std::set<std::string> baixo;
    try {
        alto = listarWin32(diretorio);
    } catch (...) {
    }
    try {
        baixo = listarNativo(diretorio);
    } catch (...) {
    }
    for (const std::string &n : baixo) {
        if (alto.find(n) == alto.end()) {
            d.visivelSoNoNativo.push_back(n);
        }
    }
    for (const std::string &n : alto) {
        if (baixo.find(n) == baixo.end()) {
            d.visivelSoNoWin32.push_back(n);
        }
    }
    return d;
}

std::vector<modelos::DivergenciaVisao> compararVarios(const std::vector<std::string> &diretorios, int limite) {
    std::vector<modelos::DivergenciaVisao> saida;
    int usados = 0;
    for (size_t i = 0; i < diretorios.size(); i = i + 1) {
        if (usados >= limite) {
            break;
        }
        try {
            modelos::DivergenciaVisao d = compararDiretorio(diretorios[i]);
            if (!d.visivelSoNoNativo.empty() || !d.visivelSoNoWin32.empty()) {
                saida.push_back(d);
            }
            usados = usados + 1;
        } catch (...) {
        }
    }
    return saida;
}

}
}
