#include <unhide/processes.h>
#include <unhide/registry.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace unhide {
namespace processos {

static std::string estreitoW(const wchar_t *w) {
    if (w == nullptr || w[0] == L'\0') {
        return std::string();
    }
    int tam = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (tam <= 1) {
        return std::string();
    }
    std::string s((size_t)tam - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), tam, nullptr, nullptr);
    return s;
}

std::vector<unsigned long> pidsPorNome(const std::string &nome) {
    std::vector<unsigned long> lista;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return lista;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    BOOL ok = Process32First(snap, &pe);
    std::string alvo = nome;
    for (size_t i = 0; i < alvo.size(); i = i + 1) {
        char c = alvo[i];
        if (c >= 'A' && c <= 'Z') {
            alvo[i] = (char)(c + 32);
        }
    }
    while (ok) {
        std::string atual = estreitoW(pe.szExeFile);
        std::string menor = atual;
        for (size_t i = 0; i < menor.size(); i = i + 1) {
            char c = menor[i];
            if (c >= 'A' && c <= 'Z') {
                menor[i] = (char)(c + 32);
            }
        }
        if (menor == alvo) {
            lista.push_back((unsigned long)pe.th32ProcessID);
        }
        ok = Process32Next(snap, &pe);
    }
    CloseHandle(snap);
    return lista;
}

std::string caminhoProcesso(unsigned long pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == nullptr) {
        return std::string();
    }
    char buf[MAX_PATH * 2];
    DWORD tam = GetModuleFileNameExA(h, nullptr, buf, sizeof(buf));
    CloseHandle(h);
    if (tam == 0) {
        return std::string();
    }
    return std::string(buf, (size_t)tam);
}

static std::string nomeBase(const std::string &caminho) {
    size_t p1 = caminho.find_last_of('\\');
    size_t p2 = caminho.find_last_of(':');
    size_t p = std::string::npos;
    if (p1 != std::string::npos) {
        p = p1;
    }
    if (p2 != std::string::npos) {
        if (p == std::string::npos || p2 > p) {
            p = p2;
        }
    }
    if (p == std::string::npos) {
        return caminho;
    }
    return caminho.substr(p + 1);
}

static std::string paraMenor(std::string s) {
    for (size_t i = 0; i < s.size(); i = i + 1) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            s[i] = (char)(c + 32);
        }
    }
    return s;
}

std::vector<InfoModulo> listarModulos(unsigned long pid) {
    std::vector<InfoModulo> saida;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);
        BOOL ok = Module32First(snap, &me);
        while (ok) {
            InfoModulo m;
            m.nome = estreitoW(me.szModule);
            m.caminho = estreitoW(me.szExePath);
            m.base = (void*)me.modBaseAddr;
            m.tamanho = (unsigned long)me.modBaseSize;
            saida.push_back(m);
            ok = Module32Next(snap, &me);
        }
        CloseHandle(snap);
    }
    if (!saida.empty()) {
        return saida;
    }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == nullptr) {
        return saida;
    }
    HMODULE mods[1024];
    DWORD necessario = 0;
    if (EnumProcessModulesEx(h, mods, sizeof(mods), &necessario, LIST_MODULES_ALL)) {
        size_t qtd = (size_t)necessario / sizeof(HMODULE);
        if (qtd > 1024) {
            qtd = 1024;
        }
        for (size_t i = 0; i < qtd; i = i + 1) {
            char buf[MAX_PATH * 2];
            DWORD t = GetModuleFileNameExA(h, mods[i], buf, sizeof(buf));
            if (t == 0) {
                continue;
            }
            std::string caminho(buf, (size_t)t);
            MODULEINFO mi;
            unsigned long tamImg = 0;
            void *base = (void*)mods[i];
            if (GetModuleInformation(h, mods[i], &mi, sizeof(mi))) {
                base = mi.lpBaseOfDll;
                tamImg = (unsigned long)mi.SizeOfImage;
            }
            InfoModulo m;
            m.nome = nomeBase(caminho);
            m.caminho = caminho;
            m.base = base;
            m.tamanho = tamImg;
            saida.push_back(m);
        }
    }
    CloseHandle(h);
    return saida;
}

bool lerMemoria(unsigned long pid, void *endereco, unsigned char *saida, unsigned long tamanho) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h == nullptr) {
        return false;
    }
    SIZE_T lidos = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)endereco, saida, (SIZE_T)tamanho, &lidos);
    CloseHandle(h);
    if (!ok) {
        return false;
    }
    return lidos == (SIZE_T)tamanho;
}

void *baseModuloLocal(const std::string &nomeModulo) {
    std::string largo = nomeModulo;
    std::wstring w = registro::paraLargo(largo);
    HMODULE h = GetModuleHandleW(w.c_str());
    return (void*)h;
}

void *enderecoFuncaoLocal(const std::string &nomeModulo, const std::string &nomeFuncao) {
    void *base = baseModuloLocal(nomeModulo);
    if (base == nullptr) {
        std::wstring w = registro::paraLargo(nomeModulo);
        HMODULE h = LoadLibraryW(w.c_str());
        if (h == nullptr) {
            return nullptr;
        }
        base = (void*)h;
    }
    HMODULE hmod = (HMODULE)base;
    FARPROC p = GetProcAddress(hmod, nomeFuncao.c_str());
    return (void*)p;
}

void *baseModuloRemoto(unsigned long pid, const std::string &nomeModulo, unsigned long *tamanhoImagem) {
    std::vector<InfoModulo> mods = listarModulos(pid);
    std::string alvo = paraMenor(nomeModulo);
    for (size_t i = 0; i < mods.size(); i = i + 1) {
        std::string atual = paraMenor(mods[i].nome);
        if (atual == alvo) {
            if (tamanhoImagem) {
                *tamanhoImagem = mods[i].tamanho;
            }
            return mods[i].base;
        }
    }
    return nullptr;
}

}
}
