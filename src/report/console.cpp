#include <unhide/console.h>
#include <windows.h>
#include <iostream>

namespace unhide {
namespace console_saida {

static void cor(int codigo) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        return;
    }
    SetConsoleTextAttribute(h, (WORD)codigo);
}

static void reset() {
    cor(7);
}

void titulo(const std::string &texto) {
    cor(11);
    std::cout << "==================================================" << std::endl;
    std::cout << texto << std::endl;
    std::cout << "==================================================" << std::endl;
    reset();
}

void etapa(const std::string &texto) {
    cor(14);
    std::cout << "[*] " << texto << std::endl;
    reset();
}

void progresso(const std::string &texto) {
    cor(8);
    std::string curto = texto;
    if (curto.size() > 110) {
        curto = curto.substr(0, 110);
    }
    std::cout << "    scanning... " << curto << "\r";
    std::cout.flush();
    reset();
}

void ok(const std::string &texto) {
    cor(10);
    std::cout << "    [OK] " << texto << std::endl;
    reset();
}

void alerta(const std::string &texto) {
    cor(12);
    std::cout << "    [!] " << texto << std::endl;
    reset();
}

void erro(const std::string &texto) {
    cor(12);
    std::cout << "    [ERRO] " << texto << std::endl;
    reset();
}

void linha() {
    std::cout << "--------------------------------------------------" << std::endl;
}

void exibirResumo(const modelos::ResultadoAnalise &r) {
    linha();
    cor(11);
    std::cout << "RESULTS" << std::endl;
    reset();
    std::cout << "Hidden files found:       " << r.arquivosOcultos.size() << std::endl;
    size_t legitimos = 0;
    for (size_t i = 0; i < r.arquivosOcultos.size(); i = i + 1) {
        if (r.arquivosOcultos[i].categoria.find("-legit") != std::string::npos) {
            legitimos = legitimos + 1;
        }
    }
    std::cout << "Legitimate system files:  " << legitimos << std::endl;
    std::cout << "Win32 vs Native diffs:    " << r.divergencias.size() << std::endl;
    size_t modulosRelevantes = 0;
    for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
        if (r.modulos[i].risco.rfind("low-", 0) != 0) {
            modulosRelevantes = modulosRelevantes + 1;
        }
    }
    std::cout << "Suspicious Explorer mods: " << modulosRelevantes << std::endl;
    std::cout << "Confirmed API hooks:      " << r.ganchos.size() << std::endl;
    std::cout << "Risky persistences:       " << r.persistencias.size() << std::endl;
    std::string prot = "unknown";
    auto it = r.configuracaoExplorer.find("HideProtected");
    if (it != r.configuracaoExplorer.end()) {
        prot = it->second;
    }
    std::cout << "Hide protected OS files:  " << prot << std::endl;
}

void exibirAchados(const modelos::ResultadoAnalise &r) {
    if (!r.arquivosOcultos.empty()) {
        linha();
        cor(12);
        std::cout << "Hidden files (" << r.arquivosOcultos.size() << "):" << std::endl;
        reset();
        for (size_t i = 0; i < r.arquivosOcultos.size(); i = i + 1) {
            const std::string &c = r.arquivosOcultos[i].categoria;
            if (c.find("-legit") != std::string::npos) {
                cor(8);
            } else if (c == "double-extension" || c == "suspicious-name" || c == "camouflaged" || c == "hidden-stream") {
                cor(14);
            } else {
                cor(15);
            }
            std::cout << "  [" << (i + 1) << "] " << r.arquivosOcultos[i].caminho << std::endl;
            reset();
            cor(8);
            std::cout << "      " << r.arquivosOcultos[i].atributos << " | " << c << std::endl;
            reset();
        }
    }
    if (!r.divergencias.empty()) {
        linha();
        cor(12);
        std::cout << "View divergences (" << r.divergencias.size() << "):" << std::endl;
        reset();
        for (size_t i = 0; i < r.divergencias.size(); i = i + 1) {
            std::cout << "  - " << r.divergencias[i].diretorio << std::endl;
            for (size_t j = 0; j < r.divergencias[i].visivelSoNoNativo.size(); j = j + 1) {
                cor(12);
                std::cout << "      [Detected!] hidden from Win32: " << r.divergencias[i].visivelSoNoNativo[j] << std::endl;
                reset();
            }
        }
    }
    if (!r.ganchos.empty()) {
        linha();
        cor(12);
        std::cout << "Detected hooks (" << r.ganchos.size() << "):" << std::endl;
        reset();
        for (size_t i = 0; i < r.ganchos.size(); i = i + 1) {
            cor(12);
            std::cout << "  - [Detected!] pid " << r.ganchos[i].pid << " " << r.ganchos[i].modulo << "!" << r.ganchos[i].funcao << " type " << r.ganchos[i].tipo << " target " << r.ganchos[i].destino << std::endl;
            reset();
        }
    }
    size_t comRisco = 0;
    for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
        if (r.modulos[i].risco.rfind("low-", 0) != 0) {
            comRisco = comRisco + 1;
        }
    }
    if (comRisco > 0) {
        linha();
        cor(12);
        std::cout << "Modules under review (" << comRisco << "):" << std::endl;
        reset();
        for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
            if (r.modulos[i].risco.rfind("low-", 0) == 0) {
                continue;
            }
            cor(14);
            std::cout << "  - [Detected!] " << r.modulos[i].caminho << std::endl;
            reset();
            cor(8);
            std::cout << "      pid " << r.modulos[i].pid << " | " << r.modulos[i].assinatura << " | " << r.modulos[i].risco << std::endl;
            reset();
        }
    }
    if (!r.persistencias.empty()) {
        linha();
        cor(12);
        std::cout << "Risky persistences (" << r.persistencias.size() << "):" << std::endl;
        reset();
        for (size_t i = 0; i < r.persistencias.size(); i = i + 1) {
            cor(14);
            std::cout << "  - [Detected!] " << r.persistencias[i].local << " " << r.persistencias[i].nome << std::endl;
            reset();
            cor(8);
            std::cout << "      " << r.persistencias[i].valor << " [" << r.persistencias[i].avaliacao << "]" << std::endl;
            reset();
        }
    }
    linha();
}

void exibirVeredito(const modelos::ResultadoAnalise &r) {
    std::string t = modelos::textoVeredito(r.veredito);
    if (r.veredito == modelos::NivelVeredito::Confirmado) {
        cor(12);
    } else if (r.veredito == modelos::NivelVeredito::Suspeito) {
        cor(14);
    } else {
        cor(10);
    }
    std::cout << "FINAL VERDICT: " << t << std::endl;
    if (r.veredito == modelos::NivelVeredito::Confirmado) {
        cor(12);
        std::cout << "Type: Detected!" << std::endl;
        reset();
    }
    reset();
    std::cout << r.resumo << std::endl;
    if (!r.evidencias.empty()) {
        std::cout << "Evidence:" << std::endl;
        for (size_t i = 0; i < r.evidencias.size(); i = i + 1) {
            std::cout << "  * " << r.evidencias[i] << std::endl;
        }
    }
}

}
}
