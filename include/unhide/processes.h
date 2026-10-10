#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace unhide {
namespace processos {

struct InfoModulo {
    std::string nome;
    std::string caminho;
    void *base = nullptr;
    unsigned long tamanho = 0;
};

std::vector<unsigned long> pidsPorNome(const std::string &nome);
std::string caminhoProcesso(unsigned long pid);
std::vector<InfoModulo> listarModulos(unsigned long pid);
bool lerMemoria(unsigned long pid, void *endereco, unsigned char *saida, unsigned long tamanho);
void *baseModuloRemoto(unsigned long pid, const std::string &nomeModulo, unsigned long *tamanhoImagem);
void *enderecoFuncaoLocal(const std::string &nomeModulo, const std::string &nomeFuncao);
void *baseModuloLocal(const std::string &nomeModulo);

}
}
