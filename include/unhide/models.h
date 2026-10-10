#pragma once
#include <string>
#include <vector>
#include <map>

namespace unhide {
namespace modelos {

enum class NivelVeredito {
    Limpo = 0,
    Informativo = 1,
    Suspeito = 2,
    Confirmado = 3
};

struct ArquivoOculto {
    std::string caminho;
    long long tamanho = 0;
    std::string atributos;
    std::string motivo;
    std::string categoria;
};

struct ModuloSuspeito {
    std::string nome;
    std::string caminho;
    unsigned long pid = 0;
    std::string processo;
    std::string assinatura;
    bool assinado = false;
    std::string risco;
};

struct GanchoDetectado {
    unsigned long pid = 0;
    std::string processo;
    std::string modulo;
    std::string funcao;
    std::string tipo;
    std::string destino;
    bool destinoExterno = false;
};

struct DivergenciaVisao {
    std::string diretorio;
    std::vector<std::string> visivelSoNoNativo;
    std::vector<std::string> visivelSoNoWin32;
};

struct PersistenciaDetectada {
    std::string local;
    std::string nome;
    std::string valor;
    std::string avaliacao;
};

struct ResultadoAnalise {
    std::string inicio;
    std::string fim;
    bool modoCompleto = false;
    std::vector<std::string> caminhosVarridos;
    std::map<std::string, std::string> configuracaoExplorer;
    std::vector<ArquivoOculto> arquivosOcultos;
    std::vector<DivergenciaVisao> divergencias;
    std::vector<ModuloSuspeito> modulos;
    std::vector<GanchoDetectado> ganchos;
    std::vector<PersistenciaDetectada> persistencias;
    NivelVeredito veredito = NivelVeredito::Limpo;
    std::string resumo;
    std::vector<std::string> evidencias;
};

std::string textoVeredito(NivelVeredito v);

}
}
