#include <unhide/hooks.h>
#include <unhide/processes.h>
#include <windows.h>
#include <cstring>
#include <vector>
#include <string>

namespace unhide {
namespace ganchos {

struct Alvo {
    const char *modulo;
    const char *funcao;
};

static Alvo alvos[] = {
    {"ntdll.dll", "NtQueryDirectoryFile"},
    {"ntdll.dll", "NtEnumerateKey"},
    {"ntdll.dll", "NtQuerySystemInformation"},
    {"kernelbase.dll", "FindFirstFileW"},
    {"kernelbase.dll", "FindNextFileW"},
    {"kernel32.dll", "FindFirstFileW"},
    {"kernel32.dll", "FindNextFileW"},
};

struct Faixa {
    unsigned long long base = 0;
    unsigned long long tamanho = 0;
};

static std::string hexEndereco(unsigned long long v) {
    char buf[32];
    _snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "0x%llX", v);
    return std::string(buf);
}

static bool dentroFaixas(unsigned long long destino, const std::vector<Faixa> &faixas) {
    for (size_t i = 0; i < faixas.size(); i = i + 1) {
        if (faixas[i].tamanho == 0) {
            continue;
        }
        if (destino >= faixas[i].base && destino < faixas[i].base + faixas[i].tamanho) {
            return true;
        }
    }
    return false;
}

static bool lerPonteiro(unsigned long pid, unsigned long long endereco, unsigned long long &saida) {
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    if (!processos::lerMemoria(pid, (void*)endereco, buf, 8)) {
        return false;
    }
    unsigned long long v = 0;
    for (int i = 0; i < 8; i = i + 1) {
        v = v | (((unsigned long long)buf[i]) << (i * 8));
    }
    saida = v;
    return true;
}

static bool analisarBytes(unsigned long pid, const unsigned char *b, int tam, unsigned long long enderecoFunc, const std::vector<Faixa> &familia, std::string &tipo, std::string &destinoTexto, bool &externo) {
    tipo = "";
    destinoTexto = "";
    externo = false;
    if (tam < 8) {
        return false;
    }
    if (b[0] == 0xE9) {
        unsigned int u = (unsigned int)b[1] | ((unsigned int)b[2] << 8) | ((unsigned int)b[3] << 16) | ((unsigned int)b[4] << 24);
        unsigned long long destino = enderecoFunc + 5 + (long long)(int)u;
        if (dentroFaixas(destino, familia)) {
            return false;
        }
        tipo = "jmp-rel32";
        destinoTexto = hexEndereco(destino);
        externo = true;
        return true;
    }
    if (b[0] == 0xFF && b[1] == 0x25) {
        unsigned int u = (unsigned int)b[2] | ((unsigned int)b[3] << 8) | ((unsigned int)b[4] << 16) | ((unsigned int)b[5] << 24);
        unsigned long long endPtr = enderecoFunc + 6 + (long long)(int)u;
        unsigned long long destino = 0;
        if (!lerPonteiro(pid, endPtr, destino)) {
            return false;
        }
        if (dentroFaixas(destino, familia)) {
            return false;
        }
        tipo = "jmp-indirect";
        destinoTexto = hexEndereco(destino);
        externo = true;
        return true;
    }
    if (tam >= 7 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25) {
        unsigned int u = (unsigned int)b[3] | ((unsigned int)b[4] << 8) | ((unsigned int)b[5] << 16) | ((unsigned int)b[6] << 24);
        unsigned long long endPtr = enderecoFunc + 7 + (long long)(int)u;
        unsigned long long destino = 0;
        if (!lerPonteiro(pid, endPtr, destino)) {
            return false;
        }
        if (dentroFaixas(destino, familia)) {
            return false;
        }
        tipo = "jmp-indirect-x64";
        destinoTexto = hexEndereco(destino);
        externo = true;
        return true;
    }
    if (b[0] == 0xCC) {
        tipo = "int3-suspicious";
        destinoTexto = hexEndereco(enderecoFunc);
        externo = true;
        return true;
    }
    if (b[0] == 0xE8) {
        unsigned int u = (unsigned int)b[1] | ((unsigned int)b[2] << 8) | ((unsigned int)b[3] << 16) | ((unsigned int)b[4] << 24);
        unsigned long long destino = enderecoFunc + 5 + (long long)(int)u;
        if (dentroFaixas(destino, familia)) {
            return false;
        }
        tipo = "external-call-in-prologue";
        destinoTexto = hexEndereco(destino);
        externo = true;
        return true;
    }
    if (b[0] == 0x90 && b[1] == 0x90 && b[2] == 0xE9) {
        tipo = "nop-jmp-suspicious";
        destinoTexto = hexEndereco(enderecoFunc);
        externo = true;
        return true;
    }
    return false;
}

std::vector<modelos::GanchoDetectado> verificarExplorer() {
    std::vector<modelos::GanchoDetectado> saida;
    std::vector<unsigned long> pids = processos::pidsPorNome("explorer.exe");
    if (pids.empty()) {
        return saida;
    }
    const char *familiares[] = {"ntdll.dll", "kernel32.dll", "kernelbase.dll"};
    int total = (int)(sizeof(alvos) / sizeof(alvos[0]));
    for (size_t k = 0; k < pids.size(); k = k + 1) {
        unsigned long pid = pids[k];
        std::vector<Faixa> familia;
        for (int f = 0; f < 3; f = f + 1) {
            unsigned long tamRemoto = 0;
            void *baseRemota = processos::baseModuloRemoto(pid, std::string(familiares[f]), &tamRemoto);
            if (baseRemota != nullptr && tamRemoto != 0) {
                Faixa fx;
                fx.base = (unsigned long long)baseRemota;
                fx.tamanho = (unsigned long long)tamRemoto;
                familia.push_back(fx);
            }
        }
        for (int a = 0; a < total; a = a + 1) {
            std::string nomeMod(alvos[a].modulo);
            std::string nomeFunc(alvos[a].funcao);
            void *localBase = processos::baseModuloLocal(nomeMod);
            void *localFunc = processos::enderecoFuncaoLocal(nomeMod, nomeFunc);
            if (localFunc == nullptr || localBase == nullptr) {
                continue;
            }
            unsigned long long desloc = (unsigned long long)localFunc - (unsigned long long)localBase;
            unsigned long tamRemoto = 0;
            void *baseRemota = processos::baseModuloRemoto(pid, nomeMod, &tamRemoto);
            if (baseRemota == nullptr) {
                continue;
            }
            unsigned long long enderecoRemoto = (unsigned long long)baseRemota + desloc;
            unsigned char buf[16];
            memset(buf, 0, sizeof(buf));
            bool ok = processos::lerMemoria(pid, (void*)enderecoRemoto, buf, sizeof(buf));
            if (!ok) {
                continue;
            }
            std::string tipo;
            std::string destinoTexto;
            bool externo = false;
            bool gancho = analisarBytes(pid, buf, (int)sizeof(buf), enderecoRemoto, familia, tipo, destinoTexto, externo);
            if (gancho && externo) {
                modelos::GanchoDetectado g;
                g.pid = pid;
                g.processo = "explorer.exe";
                g.modulo = nomeMod;
                g.funcao = nomeFunc;
                g.tipo = tipo;
                g.destino = destinoTexto;
                g.destinoExterno = true;
                saida.push_back(g);
            }
        }
    }
    return saida;
}

}
}
