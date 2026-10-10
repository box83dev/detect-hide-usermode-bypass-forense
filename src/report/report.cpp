#include <unhide/report.h>
#include <windows.h>
#include <fstream>
#include <direct.h>

namespace unhide {
namespace relatorio {

std::string agoraTexto() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[64];
    _snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%04d-%02d-%02d_%02d-%02d-%02d", (int)st.wYear, (int)st.wMonth, (int)st.wDay, (int)st.wHour, (int)st.wMinute, (int)st.wSecond);
    return std::string(buf);
}

std::string escaparJson(const std::string &texto) {
    std::string s;
    for (size_t i = 0; i < texto.size(); i = i + 1) {
        char c = texto[i];
        if (c == '"') {
            s = s + "\\\"";
        } else if (c == '\\') {
            s = s + "\\\\";
        } else if (c == '\n') {
            s = s + "\\n";
        } else if (c == '\r') {
            s = s + "\\r";
        } else if (c == '\t') {
            s = s + "\\t";
        } else if ((unsigned char)c < 0x20) {
            char buf[8];
            _snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "\\u%04x", (unsigned int)(unsigned char)c);
            s = s + std::string(buf);
        } else {
            s = s + c;
        }
    }
    return s;
}

static std::string textoNivel(modelos::NivelVeredito v) {
    return modelos::textoVeredito(v);
}

std::string salvar(const modelos::ResultadoAnalise &r, const std::string &pasta) {
    _mkdir(pasta.c_str());
    std::string base = pasta;
    if (!base.empty() && base[base.size() - 1] != '\\' && base[base.size() - 1] != ':') {
        base = base + "\\";
    }
    std::string stamp = agoraTexto();
    std::string caminhoTxt = base + "report_" + stamp + ".txt";
    std::string caminhoJson = base + "report_" + stamp + ".json";
    {
        std::ofstream txt(caminhoTxt, std::ios::out | std::ios::binary);
        txt << "UNHIDE USERMODE - FORENSIC REPORT\r\n";
        txt << "Start: " << r.inicio << "\r\n";
        txt << "End: " << r.fim << "\r\n";
        txt << "Full mode: " << (r.modoCompleto ? "YES" : "NO") << "\r\n";
        txt << "Verdict: " << textoNivel(r.veredito) << "\r\n";
        txt << "Summary: " << r.resumo << "\r\n";
        txt << "\r\nEXPLORER SETTINGS\r\n";
        for (auto &par : r.configuracaoExplorer) {
            txt << par.first << "=" << par.second << "\r\n";
        }
        txt << "\r\nHIDDEN FILES (" << r.arquivosOcultos.size() << ")\r\n";
        for (size_t i = 0; i < r.arquivosOcultos.size(); i = i + 1) {
            txt << r.arquivosOcultos[i].caminho << " | " << r.arquivosOcultos[i].atributos << " | " << r.arquivosOcultos[i].categoria << " | " << r.arquivosOcultos[i].motivo << "\r\n";
        }
        txt << "\r\nDIVERGENCES (" << r.divergencias.size() << ")\r\n";
        for (size_t i = 0; i < r.divergencias.size(); i = i + 1) {
            txt << "Directory: " << r.divergencias[i].diretorio << "\r\n";
            for (size_t j = 0; j < r.divergencias[i].visivelSoNoNativo.size(); j = j + 1) {
                txt << "  hidden-from-win32: " << r.divergencias[i].visivelSoNoNativo[j] << "\r\n";
            }
        }
        txt << "\r\nMODULES (" << r.modulos.size() << ")\r\n";
        for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
            txt << "pid " << r.modulos[i].pid << " " << r.modulos[i].caminho << " | " << r.modulos[i].assinatura << " | " << r.modulos[i].risco << "\r\n";
        }
        txt << "\r\nHOOKS (" << r.ganchos.size() << ")\r\n";
        for (size_t i = 0; i < r.ganchos.size(); i = i + 1) {
            txt << "pid " << r.ganchos[i].pid << " " << r.ganchos[i].modulo << "!" << r.ganchos[i].funcao << " " << r.ganchos[i].tipo << " -> " << r.ganchos[i].destino << " [Detected!]\r\n";
        }
        txt << "\r\nPERSISTENCES (" << r.persistencias.size() << ")\r\n";
        for (size_t i = 0; i < r.persistencias.size(); i = i + 1) {
            txt << r.persistencias[i].local << " " << r.persistencias[i].nome << " = " << r.persistencias[i].valor << " [" << r.persistencias[i].avaliacao << "]\r\n";
        }
        txt << "\r\nEVIDENCE\r\n";
        for (size_t i = 0; i < r.evidencias.size(); i = i + 1) {
            txt << "* " << r.evidencias[i] << "\r\n";
        }
    }
    {
        std::ofstream js(caminhoJson, std::ios::out | std::ios::binary);
        js << "{\n";
        js << "  \"verdict\": \"" << escaparJson(textoNivel(r.veredito)) << "\",\n";
        js << "  \"summary\": \"" << escaparJson(r.resumo) << "\",\n";
        js << "  \"files\": [\n";
        for (size_t i = 0; i < r.arquivosOcultos.size(); i = i + 1) {
            js << "    {\"path\": \"" << escaparJson(r.arquivosOcultos[i].caminho) << "\", \"category\": \"" << escaparJson(r.arquivosOcultos[i].categoria) << "\"}";
            if (i + 1 < r.arquivosOcultos.size()) {
                js << ",";
            }
            js << "\n";
        }
        js << "  ],\n";
        js << "  \"hooks\": " << r.ganchos.size() << ",\n";
        size_t modulosRelevantes = 0;
        for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
            if (r.modulos[i].risco.rfind("low-", 0) != 0) {
                modulosRelevantes = modulosRelevantes + 1;
            }
        }
        js << "  \"modules\": " << modulosRelevantes << ",\n";
        js << "  \"divergences\": " << r.divergencias.size() << "\n";
        js << "}\n";
    }
    return caminhoTxt;
}

}
}
