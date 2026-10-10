#include <unhide/persistence.h>
#include <unhide/registry.h>
#include <unhide/signature.h>
#include <windows.h>

namespace unhide {
namespace persistencias {

static std::string menorTexto(std::string s) {
    for (size_t i = 0; i < s.size(); i = i + 1) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            s[i] = (char)(c + 32);
        }
    }
    return s;
}

static void avaliarCaminho(const std::string &local, const std::string &nome, const std::string &valor, std::vector<modelos::PersistenciaDetectada> &saida) {
    if (valor.empty()) {
        return;
    }
    std::string m = menorTexto(valor);
    bool temDll = (m.find(".dll") != std::string::npos);
    if (!temDll) {
        return;
    }
    if (assinatura::caminhoSistemaConfiavel(valor)) {
        return;
    }
    std::string estado = assinatura::verificar(valor);
    modelos::PersistenciaDetectada p;
    p.local = local;
    p.nome = nome;
    p.valor = valor;
    if (estado != "valid") {
        p.avaliacao = "risk-unsigned-dll";
        saida.push_back(p);
    }
}

std::vector<modelos::PersistenciaDetectada> verificar() {
    std::vector<modelos::PersistenciaDetectada> saida;
    std::wstring chaveWin = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    std::string appInit = registro::lerValor(chaveWin, L"AppInit_DLLs", true);
    std::string hab = registro::lerValor(chaveWin, L"LoadAppInit_DLLs", true);
    if (!appInit.empty() && appInit != "0") {
        bool habilitado = (hab == "1");
        if (habilitado) {
            size_t ini = 0;
            while (ini < appInit.size()) {
                size_t fim = appInit.find_first_of("; ,", ini);
                std::string parte;
                if (fim == std::string::npos) {
                    parte = appInit.substr(ini);
                    ini = appInit.size();
                } else {
                    parte = appInit.substr(ini, fim - ini);
                    ini = fim + 1;
                }
                while (!parte.empty() && (parte[0] == ' ' || parte[0] == '"')) {
                    parte = parte.substr(1);
                }
                while (!parte.empty() && (parte[parte.size() - 1] == ' ' || parte[parte.size() - 1] == '"')) {
                    parte = parte.substr(0, parte.size() - 1);
                }
                if (!parte.empty()) {
                    avaliarCaminho("AppInit_DLLs", "AppInit_DLLs", parte, saida);
                }
            }
        }
    }
    std::wstring chaveShell = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad";
    std::map<std::string, std::string> mapa1 = registro::lerChave(chaveShell, true);
    for (auto &par : mapa1) {
        avaliarCaminho("ShellServiceObjectDelayLoad", par.first, par.second, saida);
    }
    std::wstring chaveShared = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler";
    std::map<std::string, std::string> mapa2 = registro::lerChave(chaveShared, true);
    for (auto &par : mapa2) {
        avaliarCaminho("SharedTaskScheduler", par.first, par.second, saida);
    }
    std::wstring chaveRun = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    std::map<std::string, std::string> mapa3 = registro::lerChave(chaveRun, true);
    for (auto &par : mapa3) {
        std::string v = menorTexto(par.second);
        if (v.find(".dll") != std::string::npos) {
            avaliarCaminho("Run-HKLM", par.first, par.second, saida);
        }
    }
    return saida;
}

}
}
